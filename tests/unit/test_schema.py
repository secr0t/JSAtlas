"""输出结构与 Schema 校验测试。"""

from jsatlas.api import analyze_text
from jsatlas.output.serializer import empty_result, to_dict
from jsatlas.output.validator import validate

_SAMPLE = """
const base = "https://api.example.com";
function list(p) { return axios.get("/api/list", { params: { page: p } }); }
const db = "jdbc:mysql://10.0.0.5:3306/app";
const appSecret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
"""


def test_empty_result_passes_validation():
    ok, errors, _mode = validate(empty_result())
    assert ok, errors


def test_empty_input_produces_valid_output():
    """空输入必须能产出符合 Schema 的 JSON，而不是抛异常。"""
    result = analyze_text("")
    data = to_dict(result)
    ok, errors, _mode = validate(data)
    assert ok, errors
    assert data == {"apis": [], "secrets": []}


def test_output_is_schema_valid_on_real_sample():
    data = to_dict(analyze_text(_SAMPLE))
    ok, errors, mode = validate(data)
    assert ok, f"{mode}: {errors}"


def test_report_only_has_two_top_level_keys():
    """对外契约就是 apis + secrets，不允许出现第三个顶层块。"""
    data = to_dict(analyze_text(_SAMPLE))
    assert set(data) == {"apis", "secrets"}


def test_deterministic_output():
    """同一输入跑两次必须逐字节一致 —— 否则下游没法做 diff。"""
    code = 'function a(){ return axios.post("/api/x", {data:{id:1}}); }'
    first = to_dict(analyze_text(code))
    second = to_dict(analyze_text(code))
    assert first == second
    assert first["apis"][0]["path"] == second["apis"][0]["path"]


def test_api_item_shape():
    data = to_dict(analyze_text(_SAMPLE))
    api = next(a for a in data["apis"] if a["path"] == "/api/list")
    assert api["method"] == "GET"
    assert api["params"] == {"page": ""}
    assert set(api) == {"path", "method", "params", "source"}


def test_empty_params_key_is_omitted():
    """没提取到参数时不写 `"params": {}` —— 那是纯噪声。"""
    code = 'function a(){ return axios.post("/api/noargs"); }'
    api = to_dict(analyze_text(code))["apis"][0]
    assert "params" not in api, f"空的 params 不该出现在输出里: {api}"
    assert set(api) == {"path", "method", "source"}


def test_missing_params_still_validates():
    """缺 params 必须是合法输出（= 未提取到参数），不能被校验器判非法。"""
    code = 'function a(){ return axios.post("/api/noargs"); }'
    data = to_dict(analyze_text(code))
    ok, errors, mode = validate(data)
    assert ok, f"{mode}: {errors}"


def test_params_present_when_extracted():
    """反向守住：真的有参数时必须写 params，不能因为改坏了而整体丢字段。"""
    code = 'function a(){ return axios.get("/api/q?token=abc&x="); }'
    api = to_dict(analyze_text(code))["apis"][0]
    assert "params" in api
    assert "token" in api["params"]


def test_params_type_is_still_enforced():
    """params 若存在仍必须是 dict；缺键不等于放开了类型约束。"""
    ok, errors, _ = validate({"apis": [{"path": "/a", "method": "GET",
                                       "params": [], "source": ""}],
                              "secrets": []})
    assert not ok
    assert any("params" in e for e in errors), errors


def test_secret_item_shape():
    """正则链路移除后，样本里能出的只有计算式打分命中的高熵值。"""
    data = to_dict(analyze_text(_SAMPLE))
    secret = next(s for s in data["secrets"] if s["type"] == "high_entropy_value")
    assert secret["value"] == "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    assert secret["risk_level"] in ("High", "Medium", "Low")
    assert secret["test_suggestion"]
    assert set(secret) == {"value", "type", "risk_level", "test_suggestion", "source"}
    # jdbc / 内网 IP 这类结构化线索已不再由 JSAtlas 判定
    assert not any(s["type"] == "jdbc_uri" for s in data["secrets"])


def test_secrets_sorted_by_risk_desc():
    """High 必须排在 Medium/Low 之前，下游按顺序处理即可。"""
    data = to_dict(analyze_text(_SAMPLE))
    order = {"High": 0, "Medium": 1, "Low": 2}
    levels = [order[s["risk_level"]] for s in data["secrets"]]
    assert levels == sorted(levels)


def test_source_is_carried_when_origin_given():
    data = to_dict(analyze_text(_SAMPLE, origin="https://x.com/app.js"))
    assert data["apis"], "要有输出才谈得上 source"
    assert all(a["source"] == "https://x.com/app.js" for a in data["apis"])
    assert all(s["source"] == "https://x.com/app.js" for s in data["secrets"])


def test_validator_rejects_unknown_secret_type():
    bad = {"apis": [], "secrets": [{
        "value": "x", "type": "made_up_type", "risk_level": "High",
        "test_suggestion": "", "source": "",
    }]}
    ok, errors, _mode = validate(bad)
    assert not ok
    assert any("type" in e for e in errors)


def test_validator_rejects_missing_top_level_key():
    ok, errors, _mode = validate({"apis": []})
    assert not ok
    assert any("secrets" in e for e in errors)
