"""已知真值样本的回归测试。

样本来源：JScanner2 `test/samples/scope_sample.js`（随迁移一并带到
`tests/fixtures/scope_sample.js`，内容未改）。

真值来自上游 README 里记录的实测结果：caller 召回做了"绑定作用域 + 实参元数"过滤后，
跨 module 的同名 wrapper 不会被误算进来。这三个数字一旦变化，
说明 caller 过滤逻辑被动了，必须有人明确确认。
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from jsatlas.analyzers.context.context_extractor import (  # noqa: E402
    extract_multiple_apis_from_raw_code,
)

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "scope_sample.js"

# API → 期望的 caller 数量
EXPECTED_CALLERS = {
    "/org/list": 2,     # 同 module 的 load() / loadAgain()
    "/other/list": 1,   # go() 内两次调用折叠为 1 条；wrongArity 被元数校验拦掉
    "/rest/list": 3,    # rest 参数不设上限，1/3/4 个实参全部放行
}


def _code() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_callers_match_known_truth():
    result = extract_multiple_apis_from_raw_code(_code(), list(EXPECTED_CALLERS))
    for api, expected in EXPECTED_CALLERS.items():
        data = result.get(api) or {}
        assert data.get("found"), f"{api} 未被找到"
        assert len(data.get("caller_codes") or []) == expected, (
            f"{api} 的 caller 数量应为 {expected}，实际 "
            f"{len(data.get('caller_codes') or [])}"
        )


def test_wrapper_is_recovered():
    result = extract_multiple_apis_from_raw_code(_code(), list(EXPECTED_CALLERS))
    for api in EXPECTED_CALLERS:
        wrapper = (result.get(api) or {}).get("wrapper_code") or ""
        assert api.strip("/").split("/")[-1] in wrapper, f"{api} 的 wrapper 里应包含该 API"


def test_output_is_deterministic():
    """同输入多次运行结果必须一致（上游曾因 list(set(...)) 导致顺序随机）。"""
    code = _code()
    apis = list(EXPECTED_CALLERS)
    first = extract_multiple_apis_from_raw_code(code, apis)
    for _ in range(3):
        again = extract_multiple_apis_from_raw_code(code, apis)
        assert again == first


def test_param_score_present():
    result = extract_multiple_apis_from_raw_code(_code(), list(EXPECTED_CALLERS))
    for api in EXPECTED_CALLERS:
        assert "param_score" in (result.get(api) or {})


def test_migrated_module_has_no_upstream_imports():
    """迁移件不得再依赖上游模块 —— 这是"能独立运行"的硬条件。"""
    source = (PROJECT_ROOT / "src" / "jsatlas" / "analyzers" / "context"
              / "context_extractor.py").read_text(encoding="utf-8")
    for forbidden in ("from logger import", "from config", "from processor",
                      "from infra", "from storage"):
        assert forbidden not in source, f"迁移件仍残留上游依赖: {forbidden}"

    scoring = (PROJECT_ROOT / "src" / "jsatlas" / "analyzers" / "parameters"
               / "param_scoring.py").read_text(encoding="utf-8")
    for forbidden in ("from logger import", "from config", "from processor"):
        assert forbidden not in scoring, f"param_scoring 仍残留上游依赖: {forbidden}"
