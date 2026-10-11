"""分析器单元测试。"""

import pytest

from jsatlas.analyzers.intelligence.secret_scoring import AdvancedSecretFilter, SecretMathScorer
from jsatlas.api import analyze_text
from jsatlas.pipeline.context import AnalysisOptions
from jsatlas.pipeline import registry
from jsatlas.pipeline.orchestrator import _DEFAULT_ORDER


def test_default_order_matches_registered_analyzers():
    """编排器的默认列表必须每一项都真实存在。

    历史经验：删除分析器后忘了同步 `_DEFAULT_ORDER`，名字会被 `if n in available`
    静默吞掉，退化成靠兜底追加顺序执行 —— 结果侥幸正确但顺序不可控。
    """
    available = {a.name for a in registry.all_analyzers()}
    stale = [n for n in _DEFAULT_ORDER if n not in available]
    assert not stale, f"_DEFAULT_ORDER 含未注册（多半是已删除）的分析器: {stale}"


def test_default_order_covers_all_registered():
    """注册了但没排进默认列表的分析器，要么是疏漏，要么应显式说明为何默认关闭。"""
    assert set(_DEFAULT_ORDER) == {a.name for a in registry.all_analyzers()}


# ---------------- 攻击面 ----------------
def test_api_path_and_method_detected():
    code = 'function a(){ return axios.post("/api/v1/order", {}); }'
    result = analyze_text(code)
    paths = {s.value for s in result.surfaces}
    assert "/api/v1/order" in paths
    surface = next(s for s in result.surfaces if s.value == "/api/v1/order")
    assert surface.method == "POST"


def test_method_from_object_literal():
    code = 'function a(){ return request({url:"/api/x", method:"DELETE"}); }'
    result = analyze_text(code)
    surface = next(s for s in result.surfaces if s.value == "/api/x")
    assert surface.method == "DELETE"


def test_base_url_write_point_detected():
    code = 'const service = axios.create({ baseURL: "https://api.example.com/v1" });'
    result = analyze_text(code)
    kinds = {s.kind for s in result.surfaces}
    assert "base_url" in kinds


def test_static_resources_are_not_surfaces():
    code = 'const a = "/static/logo.png"; const b = "/api/list";'
    result = analyze_text(code)
    values = {s.value for s in result.surfaces}
    assert "/api/list" in values
    assert "/static/logo.png" not in values


def test_concat_tail_fragment_is_not_an_api():
    """`'/a/b/' + id + '/delete'` 里的 `/delete` 不该变成独立接口。"""
    code = "function del(id){ return request('/api/v1/items/' + id + '/delete'); }"
    result = analyze_text(code)
    values = {s.value for s in result.surfaces}
    # 拼接表达式最左那一段保留（normalize_path 会去掉尾斜杠）
    assert "/api/v1/items" in values
    # 后续片段不是独立接口
    assert "/delete" not in values


# ---------------- 参数 ----------------
def test_query_params_from_path():
    code = 'function a(){ return fetch("/api/search?keyword=x&pageSize=20"); }'
    result = analyze_text(code)
    names = {p.name for p in result.points}
    assert "keyword" in names
    assert "pageSize" in names
    assert all(p.location_type == "query" for p in result.points)


def test_query_literal_values_are_kept():
    """能确定的值留下来，是表达式的写成空字符串。"""
    code = 'function a(){ return fetch("/api/user/detail?userId=&page=1"); }'
    result = analyze_text(code)
    values = {p.name: p.value for p in result.points}
    assert values == {"userId": "", "page": "1"}


def test_variable_concat_query_becomes_empty():
    code = "function s(kw){ return fetch('/api/search?keyword=' + kw + '&pageSize=20'); }"
    result = analyze_text(code)
    values = {p.name: p.value for p in result.points}
    assert values.get("keyword") == ""


def test_body_params_from_data_object():
    code = 'function a(){ return axios.post("/api/x", {data:{goodsId:1, quantity:2}}); }'
    result = analyze_text(code)
    body_points = [p for p in result.points if p.location_type == "body"]
    assert {p.name for p in body_points} == {"goodsId", "quantity"}
    # 同一个外层函数内，归属应当被确认
    assert all(p.surface_id for p in body_points)


def test_body_literal_value_is_kept():
    code = 'function a(){ return axios.post("/api/x", {data:{id: 1, name: "bob"}}); }'
    result = analyze_text(code)
    values = {p.name: p.value for p in result.points}
    assert values == {"id": "1", "name": "bob"}


def test_body_identifier_value_is_blank():
    code = 'function a(p){ return axios.post("/api/x", {data:{userId: p.userId}}); }'
    result = analyze_text(code)
    values = {p.name: p.value for p in result.points}
    assert values == {"userId": ""}


def test_param_score_is_exposed_with_meaning():
    code = 'function a(q){ return axios.get("/api/x", {params:q}); }'
    result = analyze_text(code)
    surface = next(s for s in result.surfaces if s.value == "/api/x")
    assert "param_score" in surface.attributes
    assert "param_score_meaning" in surface.attributes


# ---------------- 情报（严格按 JScanner2 的计算式方法） ----------------
# 上游 `-asir` 正则链路已按项目决策整体移除：它把语言包里的界面文案
# （"请输入密码"、"Login password"）当成硬编码口令，实跑 43 条全是误报。
# 现在 secrets 只有一个来源：行切片 → 熵/分词打分 → AST 上下文 → LLM 复核。
_REGEX_ONLY_TYPES = {"jdbc_uri", "private_ip", "email", "hardcoded_password",
                     "id_card", "webhook", "private_key", "sourcemap",
                     "sensitive_endpoint", "phone"}


def test_regex_secret_link_is_removed():
    """正则链路独有的类型一条都不该再出现。

    这是决策锁定：不是"暂时没跑到"，而是能力边界里已经没有正则这一路。
    """
    code = ('const d = "jdbc:mysql://10.0.0.5:3306/app";\n'
            'const mail = "admin@corp-internal.cn";\n'
            'const cfg = { password: "Zx9#kLp2Qw" };')
    result = analyze_text(code)
    subs = {i.sub_type for i in result.intelligence}
    assert not subs & _REGEX_ONLY_TYPES, f"正则链路仍在产出：{subs & _REGEX_ONLY_TYPES}"


def test_language_pack_copy_is_not_a_secret():
    """i18n 界面文案不该再被当成硬编码口令（正则链路时期的典型误报）。"""
    code = ('const lang = { password: "Login password",\n'
            '  oldPwdLabel: "Old password:",\n'
            '  tip: "Please enter new password" };')
    result = analyze_text(code)
    values = {i.value for i in result.intelligence}
    assert "Login password" not in values
    assert not any(i.sub_type == "hardcoded_password" for i in result.intelligence)


def test_every_secret_carries_risk_and_suggestion():
    """凡是 JScanner2 方法判定的机密，都必须带齐报告需要的三个字段。"""
    code = ('const k1 = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";\n'
            'const k2 = "aB3dEf7hJk2mNp5qRs8tUv1w";')
    result = analyze_text(code)
    assert result.intelligence
    for item in result.intelligence:
        assert item.attributes.get("method", "").startswith("jscanner2.")
        assert item.attributes.get("risk_level")
        assert item.attributes.get("test_suggestion")


def test_scoring_link_finds_high_entropy_value():
    result = analyze_text('const token = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";')
    item = next((i for i in result.intelligence if i.sub_type == "high_entropy_value"), None)
    assert item is not None
    assert item.detector == "statistical"
    assert item.attributes["risk_level"] in ("High", "Medium", "Low")


def test_statistical_scorer_behaves_as_expected():
    scorer = SecretMathScorer()
    # 随机串：熵高、不可分词 → 分高
    high = scorer.score("9f8e7d6c5b4a39281706f5e4d3c2b1a0")
    # 正常英文词：可分词 → P 高 → 分低
    low = scorer.score("configuration")
    assert high["score"] > low["score"]

    filt = AdvancedSecretFilter()
    assert filt.is_secret("9f8e7d6c5b4a39281706f5e4d3c2b1a0") is True
    assert filt.is_secret("configuration") is False


# ---------------- 选项 ----------------
def test_analyzer_whitelist():
    options = AnalysisOptions(analyzers=["intelligence.upstream_secret"])
    result = analyze_text('axios.get("/api/x"); const k = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";',
                          options=options)
    # 只跑密钥链路，不应产生攻击面
    assert result.surfaces == []
    assert result.intelligence


def test_syntax_error_input_is_tolerated():
    """语法错误不能让整条流水线崩掉。"""
    result = analyze_text("function broken( { var x = 'unclosed; ][ }{")
    assert result.statistics.duration_ms >= 0


# ---------------- 密钥链路：候选超过上限时不能崩 ----------------
def _many_candidates(count: int) -> str:
    """造 count 条互不相同的高熵候选（都能过打分阈值）。"""
    import hashlib

    return "\n".join(
        'const v%d = "%s";' % (i, hashlib.md5(str(i).encode()).hexdigest() + "aA1")
        for i in range(count)
    )


def test_shannon_entropy_matches_upstream_formula():
    """`_priority_sort` 依赖这个方法；上游是 `calc_E(data) * log2(len(data))`。"""
    import math

    filt = AdvancedSecretFilter()
    for value in ("9f8e7d6c5b4a39281706f5e4d3c2b1a0", "abcABC123", "aaaa"):
        assert filt.shannon_entropy(value) == pytest.approx(
            filt.scorer.calc_E(value) * math.log2(len(value)))
    assert filt.shannon_entropy("") == 0.0


def test_scan_survives_more_candidates_than_limits():
    """候选数超过 `max_ast_analysis`(50) / `max_llm`(80) 时不能抛异常。

    这里的坑：迁移时漏了 `AdvancedSecretFilter.shannon_entropy`，
    `_priority_sort` 一排序就 AttributeError —— AST 那次被 except 吞掉（上下文静默全空），
    第二次在 `scan()` 里没有 try 保护，异常一路抛到分析器，secrets 恒为 0 条。
    """
    from jsatlas.analyzers.intelligence.upstream_secret_scanner import SensitiveInfoScanner

    scanner = SensitiveInfoScanner()
    results = scanner.scan(_many_candidates(120), "many.js")
    assert results, "候选超过上限后整条链路空手而归"
    # 先在 AST 富化处裁到 max_ast_analysis(50)，所以 max_llm(80) 实际不会再触发，
    # 进入复核的最多 50 条 —— 这是上游的裁剪顺序，保持不动。
    assert len(results) == scanner.max_ast_analysis
    assert scanner.last_scan_stats["candidates"] == scanner.max_ast_analysis


def test_secret_link_reports_its_own_scale():
    """secrets 为空时，统计里要能看出是"没候选"还是"被否掉了"。"""
    result = analyze_text(_many_candidates(120))
    stats = result.statistics.analyzers.get("intelligence.upstream_secret")
    assert isinstance(stats, dict), stats
    assert stats["candidates"] == 50
    assert stats["kept"] == stats["candidates"]
