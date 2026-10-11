"""端到端流水线测试。"""

from jsatlas.api import analyze_file, analyze_text, available_analyzers
from jsatlas.output.serializer import to_dict
from jsatlas.output.validator import validate


def _fixture(name: str) -> str:
    from tests.conftest import read_fixture

    return read_fixture(name)


def test_all_analyzers_registered():
    names = {a["name"] for a in available_analyzers()}
    assert {
        "surface.path_candidates",
        "surface.base_url",
        "intelligence.upstream_secret",
        "context.api_context",
        "parameters.explicit_params",
        "parameters.upstream_pipeline",
    }.issubset(names)
    # 正则密钥链路已按项目决策移除，不该还能注册上
    assert "intelligence.upstream_regex" not in names


def test_no_stale_analyzer_names_in_default_order():
    """编排器的默认列表不能留已删除分析器的名字（会被静默吞掉）。"""
    from jsatlas.pipeline import orchestrator
    from jsatlas.pipeline.registry import all_analyzers

    available = {a.name for a in all_analyzers()}
    stale = [n for n in orchestrator._DEFAULT_ORDER if n not in available]
    missing = [n for n in available if n not in orchestrator._DEFAULT_ORDER]
    assert not stale, f"默认列表里有失效名字：{stale}"
    assert not missing, f"注册了却没排进列表：{missing}"


def test_basic_fixture_end_to_end():
    result = analyze_text(_fixture("basic.js"), origin="basic.js")
    data = to_dict(result)
    ok, errors, _mode = validate(data)
    assert ok, errors

    paths = {a["path"] for a in data["apis"]}
    assert "/api/user/create" in paths
    types = {s["type"] for s in data["secrets"]}
    # secrets 现在只有计算式来源
    assert "high_entropy_value" in types
    assert not types & {"private_ip", "jdbc_uri", "email", "hardcoded_password"}


def test_empty_fixture():
    data = to_dict(analyze_text(_fixture("empty.js")))
    ok, errors, _mode = validate(data)
    assert ok, errors
    assert data == {"apis": [], "secrets": []}


def test_syntax_error_fixture_still_produces_output():
    """解析失败也必须给出合法输出（降级为无 AST 的分析）。"""
    result = analyze_text(_fixture("syntax_error.js"))
    data = to_dict(result)
    ok, errors, _mode = validate(data)
    assert ok, errors
    assert result.statistics.parsed is False
    assert any("AST" in w for w in result.statistics.warnings)


def test_relationships_are_built():
    """关系仍在内部构建，供未来恢复证据链使用。"""
    result = analyze_text(_fixture("basic.js"))
    types = {r.type for r in result.relationships}
    assert "api_defined_in" in types


def test_analyze_file_matches_analyze_text():
    """文件输入与文本输入在内容相同时应得到一致结果（ID 只依赖内容）。"""
    from tests.conftest import fixture

    by_file = analyze_file(str(fixture("basic.js")))
    by_text = analyze_text(_fixture("basic.js"), origin=str(fixture("basic.js")))
    assert {s.id for s in by_file.surfaces} == {s.id for s in by_text.surfaces}


def test_proximity_link_is_off_by_default():
    """默认不按行号猜测关联。"""
    from jsatlas.pipeline.context import AnalysisOptions

    result = analyze_text(_fixture("basic.js"))
    assert not any(r.type == "intel_near_api" for r in result.relationships)

    result = analyze_text(_fixture("basic.js"),
                          options=AnalysisOptions(proximity_link_lines=50))
    assert any(r.type == "intel_near_api" for r in result.relationships)
