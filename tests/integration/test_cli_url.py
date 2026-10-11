"""CLI 的 URL 入口集成测试。

关注"失败语义"：单个 URL 失败必须体现在退出码上，否则脚本无从判断；
批量时则要容错 —— 一个挂了不能连累其他结果。

无论单目标还是多目标，输出形态都一样：`{"apis": [...], "secrets": [...]}`，
多资源合并进同一份清单，靠每条的 source 区分出处。
"""

from __future__ import annotations

import json
from pathlib import Path

from conftest import url_of
from jsatlas.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _stdout_json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def _run_capture(capsys, argv, code_holder: dict):
    """一次性取回 stdout / stderr —— 两次 readouterr 会互相清空。"""
    code_holder["code"] = main(argv)
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.err


def test_cli_single_url(server, capsys):
    code = main([url_of(server, "basic.js"), "--indent", "0"])
    data = _stdout_json(capsys)
    assert code == 0
    assert set(data) == {"apis", "secrets"}
    assert data["apis"]
    assert all(a["source"] == url_of(server, "basic.js") for a in data["apis"])


def test_cli_single_url_404_returns_nonzero(server, capsys):
    """单个目标失败必须退出码非 0 —— 不能输出一份空结果让人误判。"""
    code = main([url_of(server, "missing.js")])
    assert code == 2
    assert "404" in capsys.readouterr().err


def test_cli_mixed_url_and_file(server, capsys):
    """多目标合并成一份清单，source 各归各位。"""
    url = url_of(server, "basic.js")
    code = main([url, str(FIXTURES / "basic.js"), "--indent", "0"])
    data = _stdout_json(capsys)
    assert code == 0
    assert set(data) == {"apis", "secrets"}
    sources = {a["source"] for a in data["apis"]}
    assert sources == {url, str(FIXTURES / "basic.js")}


def test_cli_batch_partial_failure(server, capsys):
    """批量时容错：失败的资源不产出结果，成功的照常，退出码告警。"""
    code = main([
        url_of(server, "missing.js"),
        url_of(server, "basic.js"),
        "--indent", "0",
    ])
    data = _stdout_json(capsys)
    assert code == 1
    assert data["apis"], "成功的那个资源仍然要有输出"


def test_cli_validate_on_url_result(server, capsys):
    holder: dict = {}
    data, err = _run_capture(capsys, [url_of(server, "basic.js"), "--indent", "0",
                                      "--validate"], holder)
    assert holder["code"] == 0
    assert "通过" in err
    assert set(data) == {"apis", "secrets"}
