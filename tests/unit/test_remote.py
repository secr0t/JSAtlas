"""远程 URL 输入的单元测试。

全部用一个进程内的本地 HTTP 服务，不依赖外网 —— 保证离线可跑。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import url_of  # noqa: F401 - 由 tests/conftest.py 提供
from jsatlas.inputs.remote import (
    FetchError,
    FetchPolicy,
    from_url,
    from_urls,
    is_url,
)
from jsatlas.inputs.source import MAX_SOURCE_BYTES

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# ---------------- is_url ----------------

def test_is_url():
    assert is_url("https://example.com/a.js")
    assert is_url("http://127.0.0.1:8080/x.js")
    assert not is_url("app.js")
    assert not is_url("C:/tmp/app.js")
    assert not is_url("ftp://example.com/a.js")
    assert not is_url("")
    assert not is_url(None)


# ---------------- 正常获取 ----------------

def test_from_url_basic(server):
    src = from_url(url_of(server, "basic.js"))
    assert src.input_type == "url"
    assert src.error is None
    assert not src.truncated
    assert "axios" in src.text
    assert src.attributes["http_status"] == 200
    assert src.attributes["fetched_bytes"] == len(src.text.encode("utf-8"))
    assert src.attributes["redirected"] is False


def test_from_url_content_matches_file(server):
    """URL 拿到内容应和直接读文件一致 —— URL 只是另一种入口，不改变语义。"""
    src = from_url(url_of(server, "basic.js"))
    assert src.text == (FIXTURES / "basic.js").read_text(encoding="utf-8")


def test_from_url_with_custom_header(server):
    """自定义请求头能传出去（带 Cookie 抓需鉴权的 JS 靠这个）。"""
    policy = FetchPolicy(headers={"X-Test": "1", "Cookie": "session=abc"})
    src = from_url(url_of(server, "basic.js"), policy)
    assert src.error is None and src.text


# ---------------- 边界与错误处理 ----------------

def test_from_url_rejects_non_http():
    for bad in ("ftp://example.com/a.js", "file:///etc/passwd", "not-a-url"):
        with pytest.raises(FetchError) as exc:
            from_url(bad)
        assert "只支持 http / https" in str(exc.value) or "缺少主机名" in str(exc.value)


def test_from_url_404(server):
    with pytest.raises(FetchError) as exc:
        from_url(url_of(server, "does_not_exist.js"))
    assert exc.value.status == 404


def test_from_url_connection_refused():
    """端口没人监听时必须是明确的 FetchError，不能是裸 ConnectionError。"""
    with pytest.raises(FetchError):
        from_url("http://127.0.0.1:1/nope.js", FetchPolicy(timeout=(1.0, 1.0)))


def test_from_url_truncates_at_max_bytes(server):
    """超限要截断并标记 —— 不能把几 MB 的 bundle 全吃进来。"""
    src = from_url(url_of(server, "basic.js"), FetchPolicy(max_bytes=10))
    assert src.truncated is True
    assert len(src.text.encode("utf-8")) <= 10
    assert src.attributes["truncated_at_bytes"] == 10


# ---------------- 批量 ----------------

def test_from_urls_partial_failure_does_not_break_batch(server):
    """一个挂了不能连累其他 —— 批量扫描时这是常态。"""
    good = url_of(server, "basic.js")
    bad = url_of(server, "missing.js")
    sources = from_urls([bad, good, "ftp://x/y.js"])
    assert len(sources) == 3
    assert sources[0].error and not sources[0].text
    assert sources[1].text and sources[1].error is None
    assert sources[2].error


def test_from_urls_empty():
    assert from_urls([]) == []


def test_from_urls_preserves_order(server):
    names = ["basic.js", "scope_sample.js", "basic.js"]
    sources = from_urls([url_of(server, n) for n in names])
    assert [s.origin for s in sources] == [url_of(server, n) for n in names]


# ---------------- 依赖降级 ----------------

def test_urllib_fallback_without_requests(server, monkeypatch):
    """没有 requests 时要能退到标准库，URL 输入不应强制装第三方库。"""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "requests" or name.startswith("requests."):
            raise ImportError("模拟未安装 requests")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    src = from_url(url_of(server, "basic.js"))
    assert src.text
    assert src.attributes["http_client"] == "urllib"


# ---------------- 策略默认值 ----------------

def test_policy_defaults_are_conservative():
    policy = FetchPolicy()
    assert policy.verify is True           # 默认校验证书
    # 默认不限字节：不做源码大小上限，需要自保时显式传 max_bytes
    assert policy.max_bytes == 0
    assert MAX_SOURCE_BYTES == 0
    assert policy.max_redirects >= 1
    assert policy.timeout[0] < policy.timeout[1]  # 连接超时快于读取超时
