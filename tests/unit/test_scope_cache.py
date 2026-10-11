"""验证声明列表缓存的等价性与隔离性（见 docs/perf-scope-cache.md）。

缓存只对纯函数 `_collect_decls_in_subtree` 做记忆化，判定逻辑不动。
这一组测试守住三条边界：
1. 加缓存后的输出与原实现逐条一致（优化不改行为）；
2. 缓存每次调用结束即清空，绝不跨文件复用（node.id 是指针，跨树复用会错位）；
3. 缓存确实产生了命中（同一棵树里共享作用域被复用）。
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import jsatlas.analyzers.context.context_extractor as ce  # noqa: E402

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "scope_sample.js"
APIS = ["/org/list", "/other/list", "/rest/list"]


def _code() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_cached_equals_uncached():
    """加缓存后的输出必须与原实现逐条一致。"""
    cached = ce.extract_multiple_apis_from_raw_code(_code(), list(APIS))

    original_collect = ce._collect_decls_in_subtree
    ce._collect_decls_in_subtree = ce._collect_decls_in_subtree_uncached
    try:
        uncached = ce.extract_multiple_apis_from_raw_code(_code(), list(APIS))
    finally:
        ce._collect_decls_in_subtree = original_collect

    assert cached == uncached


def test_cache_cleared_after_call():
    """每次提取结束缓存必须清空（否则下一棵树可能复用同名 node.id）。"""
    ce.extract_multiple_apis_from_raw_code(_code(), list(APIS))
    assert getattr(ce._DECL_CACHE, "map", None) is None


def test_cache_isolated_across_calls():
    """连续两次不同输入的提取互不污染：结果与关掉缓存时逐条一致。"""
    code_a = 'function f(){ var base = "/api"; request("/api/a", base); }'
    code_b = 'function g(){ var base = "/v2"; request("/v2/b", base); }'

    ra = ce.extract_multiple_apis_from_raw_code(code_a, ["/api/a"])
    rb = ce.extract_multiple_apis_from_raw_code(code_b, ["/v2/b"])

    assert ra["/api/a"].get("found"), "样本本身应命中，否则这条测试失去意义"
    assert rb["/v2/b"].get("found")
    assert getattr(ce._DECL_CACHE, "map", None) is None

    # 关掉缓存重跑：若缓存跨调用残留（node.id 是指针地址，会错位命中另一棵树），
    # 这里就会对不上
    original = ce._collect_decls_in_subtree
    ce._collect_decls_in_subtree = ce._collect_decls_in_subtree_uncached
    try:
        assert ce.extract_multiple_apis_from_raw_code(code_a, ["/api/a"]) == ra
        assert ce.extract_multiple_apis_from_raw_code(code_b, ["/v2/b"]) == rb
    finally:
        ce._collect_decls_in_subtree = original


def test_cache_produces_hits():
    """同一棵树里共享的作用域节点应被复用：真实收集次数 < 查询次数。"""
    calls = {"total": 0, "uncached": 0}
    orig_uncached = ce._collect_decls_in_subtree_uncached
    orig_cached = ce._collect_decls_in_subtree

    def counting_uncached(node, decls):
        calls["uncached"] += 1
        return orig_uncached(node, decls)

    def counting_cached(node, decls):
        calls["total"] += 1
        return orig_cached(node, decls)

    ce._collect_decls_in_subtree_uncached = counting_uncached
    ce._collect_decls_in_subtree = counting_cached
    try:
        ce.extract_multiple_apis_from_raw_code(_code(), list(APIS))
    finally:
        ce._collect_decls_in_subtree_uncached = orig_uncached
        ce._collect_decls_in_subtree = orig_cached

    assert calls["total"] > 0
    assert calls["uncached"] < calls["total"], (
        f"缓存应产生命中，但 uncached={calls['uncached']} == total={calls['total']}"
    )