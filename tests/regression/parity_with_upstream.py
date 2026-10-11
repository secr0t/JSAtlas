"""与上游 JScanner2 的对拍校验。

为什么必须有这个脚本：
`context_extractor.py` / `param_scoring.py` 是**逐字迁移**的，正确性建立在
"迁移前后行为完全一致"之上。光靠单测证明不了这一点 —— 必须把上游实现真跑起来，
喂同样的输入，逐字段比。

对拍对象：上游生产实现 `processor/js/context/context_extractor.py`
（不是 `test/context_recall/` 那份副本，避免自己和自己比）。

上游生产模块 import 了 `processor.js.context.parse`，而后者会牵出
`logger` → `config.config` → `infra.feishu`（可能发网络告警）。
因此这里用 shim 替换掉 `parse`，只保留一个裸 tree-sitter parser ——
替换的是**依赖**，不是算法，比对仍然有效。

运行：
    python -m pytest tests/regression/parity_with_upstream.py -v
    python tests/regression/parity_with_upstream.py            # 直接跑，输出可读报告

环境变量：
    JSCANNER2_ROOT      上游项目根目录（默认 C:\\Users\\Cheng\\Desktop\\JScanner2）
    JSATLAS_BIG_SAMPLE  可选的大样本 .js 路径，设置后会额外跑一次大样本对拍
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
import types
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

UPSTREAM_ROOT = Path(os.environ.get("JSCANNER2_ROOT", r"C:\Users\Cheng\Desktop\JScanner2"))
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# 对拍字段。这 5 个字段决定了下游能拿到什么，必须逐条一致。
COMPARE_FIELDS = ("found", "api_url", "wrapper_code", "caller_codes", "param_score")


# ---------------------------------------------------------------- 加载上游
def _ensure_package(name: str) -> None:
    """在 sys.modules 里造出空的包壳，供后续按完整名加载模块。"""
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        full = ".".join(parts[:i])
        if full in sys.modules:
            continue
        module = types.ModuleType(full)
        module.__path__ = []  # 标记为包
        sys.modules[full] = module
        if i > 1:
            setattr(sys.modules[".".join(parts[: i - 1])], parts[i - 1], module)


def _load_module(full_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(full_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载 {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


def _build_parse_shim():
    """替换上游 `processor.js.context.parse`：只提供裸 parser，不带 logger 副作用。"""
    import tree_sitter_javascript
    from tree_sitter import Language, Parser

    parser = Parser(Language(tree_sitter_javascript.language()))
    shim = types.ModuleType("processor.js.context.parse")
    shim.get_parser = lambda: parser
    shim.get_logger = lambda name=None: logging.getLogger(name or "upstream")
    sys.modules["processor.js.context.parse"] = shim
    setattr(sys.modules["processor.js.context"], "parse", shim)
    return shim


def load_upstream():
    """加载上游生产版 context_extractor；返回其公开入口函数。"""
    context_file = UPSTREAM_ROOT / "processor" / "js" / "context" / "context_extractor.py"
    scoring_file = UPSTREAM_ROOT / "processor" / "js" / "context" / "param_scoring.py"
    if not context_file.exists():
        raise FileNotFoundError(f"找不到上游实现: {context_file}")

    _ensure_package("processor.js.context")
    _build_parse_shim()
    _load_module("processor.js.context.param_scoring", scoring_file)
    module = _load_module("processor.js.context.context_extractor", context_file)
    return module.extract_multiple_apis_from_raw_code


def load_jsatlas():
    from jsatlas.analyzers.context.context_extractor import (
        extract_multiple_apis_from_raw_code,
    )

    return extract_multiple_apis_from_raw_code


# ---------------------------------------------------------------- 候选 API
def collect_api_candidates(code: str, limit: int = 300) -> List[str]:
    """用 JSAtlas 自己的攻击面分析器产出候选 API，保证两侧喂同样的输入。"""
    from jsatlas.api import analyze_text
    from jsatlas.pipeline.context import AnalysisOptions

    options = AnalysisOptions(analyzers=["surface.path_candidates"])
    result = analyze_text(code, options=options)
    values = [s.value for s in result.surfaces if s.kind in ("api_path", "url")]
    return sorted(values)[:limit]


# ---------------------------------------------------------------- 比对
def compare(code: str, targets: List[str]) -> Dict[str, object]:
    upstream_fn = load_upstream()
    jsatlas_fn = load_jsatlas()

    upstream_result = upstream_fn(code, targets)
    jsatlas_result = jsatlas_fn(code, targets)

    matched = 0
    mismatched: List[Dict[str, object]] = []
    for target in targets:
        left = upstream_result.get(target) or {}
        right = jsatlas_result.get(target) or {}
        diffs = [f for f in COMPARE_FIELDS if left.get(f) != right.get(f)]
        if diffs:
            mismatched.append({
                "api": target,
                "fields": diffs,
                "upstream": {f: left.get(f) for f in diffs},
                "jsatlas": {f: right.get(f) for f in diffs},
            })
        else:
            matched += 1
    return {"total": len(targets), "matched": matched, "mismatched": mismatched}


def _shorten(value, limit: int = 80) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + f"...(+{len(text) - limit})"


def run(sample_path: Path, limit: int = 300) -> int:
    code = sample_path.read_text(encoding="utf-8", errors="replace")
    targets = collect_api_candidates(code, limit=limit)
    if not targets:
        print(f"[SKIP] {sample_path.name}: 未提取到候选 API")
        return 0

    report = compare(code, targets)
    total = int(report["total"])
    matched = int(report["matched"])
    print(f"[{'PASS' if matched == total else 'FAIL'}] {sample_path.name}: "
          f"{matched}/{total} 条一致（候选 API {len(targets)} 个）")

    for item in report["mismatched"][:20]:
        print(f"  ✗ {item['api']}  字段: {item['fields']}")
        for field in item["fields"]:
            print(f"      上游    {field} = {_shorten(item['upstream'][field])}")
            print(f"      JSAtlas {field} = {_shorten(item['jsatlas'][field])}")
    return 0 if matched == total else 1


def main() -> int:
    samples: List[Path] = [FIXTURES / "scope_sample.js"]
    big = os.environ.get("JSATLAS_BIG_SAMPLE", "")
    if big and Path(big).exists():
        samples.append(Path(big))

    print(f"上游: {UPSTREAM_ROOT}")
    exit_code = 0
    for sample in samples:
        exit_code |= run(sample)
    print("总计:", "全部一致" if exit_code == 0 else "存在不一致")
    return exit_code


# ---------------------------------------------------------------- pytest
def test_parity_with_upstream():
    import pytest

    if not (UPSTREAM_ROOT / "processor" / "js" / "context" / "context_extractor.py").exists():
        pytest.skip(f"未找到上游 JSCANNER2_ROOT={UPSTREAM_ROOT}，跳过对拍")

    report = compare((FIXTURES / "scope_sample.js").read_text(encoding="utf-8"),
                     ["/org/list", "/other/list", "/rest/list"])
    assert report["mismatched"] == [], f"与上游不一致: {report['mismatched']}"
    assert report["total"] == 3


def test_parity_on_all_candidates():
    import pytest

    if not (UPSTREAM_ROOT / "processor" / "js" / "context" / "context_extractor.py").exists():
        pytest.skip(f"未找到上游 JSCANNER2_ROOT={UPSTREAM_ROOT}，跳过对拍")

    code = (FIXTURES / "scope_sample.js").read_text(encoding="utf-8")
    targets = collect_api_candidates(code, limit=50)
    assert targets, "样本里应能提取到候选 API"
    report = compare(code, targets)
    assert report["matched"] == report["total"], report["mismatched"]


if __name__ == "__main__":
    raise SystemExit(main())
