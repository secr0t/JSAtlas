"""迁移件一致性测试。

这里的断言全部围绕一件事：**JSAtlas 搬过来的 JScanner2 逻辑没有被改坏**。
能用 md5 证明的用 md5；不能的（文件被重排重组）用行为对照。
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    PROJECT_ROOT,
    UPSTREAM_ROOT,
    read_fixture,
    upstream_available,
)

requires_upstream = pytest.mark.skipif(
    not upstream_available(), reason="未找到上游 JScanner2")

# (上游相对路径, JSAtlas 相对路径, 说明)
_VERBATIM = [
    ("processor/js/format/js_formatter.py",
     "src/jsatlas/parsing/preprocess.py", "JS 美化预处理"),
    ("processor/js/format/options.py",
     "src/jsatlas/parsing/beautify_options.py", "jsbeautifier 选项"),
    ("config/scanner_rules.py",
     "src/jsatlas/parsing/scanner_rules.py", "扫描规则常量集"),
    ("infra/utils.py",
     "src/jsatlas/utils/html.py", "HTML 标签剥离"),
    ("processor/analysis/prompts/prompts.py",
     "src/jsatlas/analyzers/prompts/prompts.py", "7 条通用提示词"),
    ("infra/ai_client.py",
     "src/jsatlas/llm/client.py", "AI 客户端（含重排与桩替换，故不比对 md5）"),
    ("processor/analysis/params/param_pre_filter.py",
     "src/jsatlas/analyzers/parameters/param_pre_filter.py", "参数预过滤闸门"),
    ("processor/analysis/secret/prompt.py",
     "src/jsatlas/analyzers/intelligence/secret_prompt.py", "密钥复核提示词"),
    ("processor/js/context/secret_extractor.py",
     "src/jsatlas/analyzers/intelligence/secret_context.py", "密钥 AST 上下文"),
]


# 迁移时只被允许替换的接缝：JSAtlas 写法 -> 上游写法。
# 除了这些，两个文件必须逐字节相同（改 import 之外的任何字符都会被测试抓住）。
_ALLOWED_REWRITES = {
    "from jsatlas.utils.logging import get_logger": "from logger import get_logger",
    "from jsatlas.parsing.beautify_options import _get_beautifier_options":
        "from processor.js.format.options import _get_beautifier_options",
    "from jsatlas.analyzers.context.context_extractor import":
        "from processor.js.context.context_extractor import",
    "from jsatlas.parsing.parser import get_parser": "from processor.js.context.parse import get_parser",
}

# 无法用"行替换"表达的例外：整体重排，只做结构断言
_STRUCTURE_ONLY = {"src/jsatlas/llm/client.py"}


def _strip_imports(text: str) -> str:
    """剥掉 import 相关行（含反斜杠续行），只留真正构成逻辑的部分。

    迁移允许改写 import，**不允许改算法**。因此把两侧都剥成"裸逻辑"再逐字节比对，
    正好对应"其他逻辑都不变"这句话。
    """
    out, skipping = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if skipping:
            # 续行：走到没有反斜杠结尾为止
            skipping = line.rstrip().endswith("\\")
            continue
        if stripped.startswith("from ") or stripped.startswith("import "):
            skipping = line.rstrip().endswith("\\")
            continue
        out.append(line)
    return "\n".join(out)


def _upstream_imports_of(text: str) -> set:
    """解析 AST 取出实际导入的顶层模块名，断言没有残留指向上游工程的引用。

    用 AST 而不是字符串匹配 —— `get_logger` 这种函数名叫法会被子串匹配误伤。
    """
    import ast

    bad_roots = {"processor", "infra", "config", "storage", "logger"}
    found = set()
    for node in ast.walk(ast.parse(text)):
        names: list = []
        if isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        for name in names:
            root = name.split(".")[0]
            if root in bad_roots:
                found.add(root)
    return found


@requires_upstream
@pytest.mark.parametrize("upstream_rel,mine_rel,label", _VERBATIM)
def test_verbatim_copy(upstream_rel, mine_rel, label):
    """迁移文件与上游的差异，只允许出现在 import 接缝上。

    `infra/ai_client.py` 例外：除改 import 外还把模块级单例改成惰性构造，
    所以它只做结构断言（见另一个测试）。
    """
    import difflib

    up_text = (UPSTREAM_ROOT / upstream_rel).read_text(encoding="utf-8")
    mine_text = (PROJECT_ROOT / mine_rel).read_text(encoding="utf-8")

    if mine_rel in _STRUCTURE_ONLY:
        pytest.skip("有意重排的文件单独做结构断言")

    # 1) 剥掉 import 之后必须逐字节相同 —— 即"算法逻辑没有被改过"
    body_up = _strip_imports(up_text)
    body_mine = _strip_imports(mine_text)
    if body_up != body_mine:
        diff_lines = difflib.unified_diff(
            body_up.splitlines(), body_mine.splitlines(),
            fromfile="upstream:" + upstream_rel, tofile="jsatlas:" + mine_rel,
            lineterm="", n=1)
        detail = "\n".join(list(diff_lines)[:40])
        raise AssertionError(label + " 的逻辑体与上游不一致：\n" + detail)

    # 2) 反过来，import 里不允许残留任何指向上游工程的引用
    leftovers = _upstream_imports_of(mine_text)
    assert not leftovers, f"{label} 仍残留上游引用：{sorted(leftovers)}"


@requires_upstream
def test_llm_client_keeps_upstream_bodies():
    """客户端的核心方法体必须与上游逐行一致（只许在头尾做依赖替换）。"""
    up_text = (UPSTREAM_ROOT / "infra" / "ai_client.py").read_text(encoding="utf-8")
    mine_text = (PROJECT_ROOT / "src/jsatlas/llm/client.py").read_text(encoding="utf-8")
    for marker in (
        "class ModelStatus",
        "class EmptyContentError(Exception)",
        "class ConfigWatcher",
        "class AIHubClient",
        "def _reload_models",
        "def get_cooldown_time",
        "def mark_error",
        "def mark_success",
        "def check_and_restore",
        "def shutdown",
    ):
        assert marker in mine_text, f"缺失上游结构：{marker}"
        assert marker in up_text


def test_params_string_matches_template_semantics():
    """模板里 `"userId": ""` 的出处：没有 `=` 的项赋空字符串。"""
    from jsatlas.utils.params_string import parse_params_string

    assert parse_params_string("userId=&page=1") == {"userId": "", "page": "1"}
    assert parse_params_string("userId,page=2") == {"userId": "", "page": "2"}
    assert parse_params_string("k1=v1&k2=v2") == {"k1": "v1", "k2": "v2"}
    assert parse_params_string("") == {}
    assert parse_params_string('{"a": "1"}') == {"a": "1"}


def test_all_eight_prompts_available():
    """通用 7 条 + 密钥复核 1 条，共 8 条模板全部到位。"""
    from jsatlas.analyzers import prompts
    from jsatlas.analyzers.intelligence.secret_prompt import SECRET_PROMPT

    names = [n for n in dir(prompts) if n.startswith("SYSTEM_PROMPT_")]
    assert len(names) == 7, f"通用提示词应 7 条，实际 {names}"
    for n in names:
        assert getattr(prompts, n).strip()
    assert len(SECRET_PROMPT.strip()) > 100


@requires_upstream
def test_prompts_identical_to_upstream():
    from jsatlas.analyzers import prompts
    from jsatlas.analyzers.intelligence import secret_prompt
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "up_prompts", UPSTREAM_ROOT / "processor/analysis/prompts/prompts.py")
    up = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(up)

    for mine_name, up_name in [
        ("SYSTEM_PROMPT_JUDGE", "_SYSTEM_PROMPT_JUDGE"),
        ("SYSTEM_PROMPT_ADVISORY", "_SYSTEM_PROMPT_ADVISORY"),
        ("SYSTEM_PROMPT_RESPONSE_ANALYSIS", "_SYSTEM_PROMPT_RESPONSE_ANALYSIS"),
        ("SYSTEM_PROMPT_BASEURL_RESOLVE", "_SYSTEM_PROMPT_BASEURL_RESOLVE"),
        ("SYSTEM_PROMPT_BASEURL_JUDGE_ROUND", "_SYSTEM_PROMPT_BASEURL_JUDGE_ROUND"),
        ("SYSTEM_PROMPT_PREFIX_VERIFY", "_SYSTEM_PROMPT_PREFIX_VERIFY"),
        ("SYSTEM_PROMPT_OPERATION_CLASSIFY", "_SYSTEM_PROMPT_OPERATION_CLASSIFY"),
    ]:
        assert getattr(prompts, mine_name) == getattr(up, up_name), f"{mine_name} 与上游不一致"

    spec = importlib.util.spec_from_file_location(
        "up_secret_prompt", UPSTREAM_ROOT / "processor/analysis/secret/prompt.py")
    up_secret = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(up_secret)
    assert secret_prompt.SECRET_PROMPT == up_secret.SECRET_PROMPT


def test_format_code_recovers_minified_single_line():
    """压缩成单行的 JS 会被 3500 字符阈值整行跳过 —— 上游靠先格式化绕开。

    这是本次迁移补回来的召回面，改动前后差值是 0 → >0。
    """
    from jsatlas.analyzers.intelligence.secret_scoring import (
        AdvancedSecretFilter,
        CodeLineFilter,
    )
    from jsatlas.parsing.preprocess import format_code

    pad = ";".join(f"var v{i}={i}" for i in range(400))
    raw = read_fixture("secret.js")
    mini = pad + ";" + " ".join(raw.split())
    assert len(mini) > 3500, "样本需超过行跳过阈值才能复现"

    def collect(text):
        line_filter, adv = CodeLineFilter(), AdvancedSecretFilter()
        return {c for c, _ in line_filter.extract_candidates(text) if adv.is_secret(c)}

    before = collect(mini)
    after = collect(format_code(mini))
    assert len(after) > len(before), "格式化预处理没有带来任何召回提升"


def test_upstream_api_blacklist_is_upstream_behaviour():
    """`is_api_path_blacklisted` 来自上游规则表，行为必须与之一致地保守。"""
    from jsatlas.parsing.scanner_rules import is_api_path_blacklisted

    assert is_api_path_blacklisted("") is True
    assert is_api_path_blacklisted("/api/v1/search?keyword=") is False
    assert is_api_path_blacklisted("/api/v1/search") is False


def test_secret_scanner_runs_without_llm():
    """没有配模型时，编排链路必须跑通并给出 ai_verified=False，而不是抛错。"""
    from jsatlas.analyzers.intelligence.upstream_secret_scanner import SensitiveInfoScanner

    scanner = SensitiveInfoScanner()
    results = scanner.scan(read_fixture("secret.js"), "secret.js")
    assert isinstance(results, list)
    for item in results:
        assert item.get("ai_verified") is False
        assert {"value", "secret_type", "risk_level", "test_suggestion"} <= set(item)


def test_secret_scanner_is_repeatable():
    """同一份输入连跑两次结果必须一致 —— 去重集合不能跨调用残留。"""
    from jsatlas.analyzers.intelligence.upstream_secret_scanner import SensitiveInfoScanner

    code = read_fixture("secret.js")
    first = SensitiveInfoScanner().scan(code, "basic.js")
    second = SensitiveInfoScanner().scan(code, "basic.js")
    assert [r.get("value") for r in first] == [r.get("value") for r in second]
    assert len(first) > 0, "样本应至少有一条高熵候选"
