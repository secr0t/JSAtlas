"""锁住一条真实踩过的坑：LLM 复核拿到的是 None client。

现象（用户实际遇到的）：

    🚀 AIHubClient (SDK版) 初始化完成 | 代理模型数：1
    🚀 Sending 8 candidates to LLM...
    ⚠️ [LLM] 调用失败 (Attempt 1/2): 'NoneType' object has no attribute 'chat'
    ⚠️ [LLM] 调用失败 (Attempt 2/2): 'NoneType' object has no attribute 'chat'
    ⚠️ [LLM] 调用失败 (Attempt 3/2): 'NoneType' object has no attribute 'chat'
    ❌ [LLM] 所有重试失败...

根因：上游 `SensitiveInfoScanner(client)` 的 client 是**必传**的模块级单例，
所以上游写 `LLMSecretVerifier(client)` 永远拿得到东西。JSAtlas 把 client 改成
惰性解析（允许传 None），但迁移时把原样入参传给了 verifier ——
`LLMSecretVerifier(client if client is not None else None)` 恒为 None。

结果就是：明明 Key 配好了、客户端也初始化成功了，复核阶段却拿 None 去调 `.chat`，
重试三次全废，还看不出真正原因。

本文件把三个环节钉死：解析、传递、以及"拿不到就降级而不是重试"。
"""

from __future__ import annotations

import pytest

from jsatlas.analyzers.intelligence import upstream_secret_scanner as mod


@pytest.fixture(autouse=True)
def _fresh_dedup():
    """每个用例换一套去重集合。

    `_AI_CANDIDATE_DEDUP` / `_OUTPUT_LINE_DEDUP` 是模块级全局，跨用例残留 ——
    两个用例若用了同一行源码，后一个会被判成"已输出过"而拿到空结果。
    """
    mod._AI_CANDIDATE_DEDUP = mod.MemoryDedup("ai_candidates")
    mod._OUTPUT_LINE_DEDUP = mod.MemoryDedup("output_lines")
    yield


class _FakeClient:
    """记录是否真的被调用过。"""

    def __init__(self):
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        return '{"0": {"is_secret": false}}'


@pytest.fixture
def llm_ready(monkeypatch):
    """让模块里的 llm_available() 返回 True，get_client() 返回一个假客户端。"""
    fake = _FakeClient()

    monkeypatch.setattr(mod, "llm_available", lambda: True)
    monkeypatch.setattr(mod, "get_client", lambda: fake)
    return fake


def test_verifier_gets_the_resolved_client(llm_ready):
    """verifier 手上的 client 必须是解析出来的那个，不能是 None。"""
    scanner = mod.SensitiveInfoScanner()

    assert scanner.client is llm_ready, "scanner 自己没解析出 client"
    assert scanner.llm_verifier.client is llm_ready, (
        "verifier 拿到的是 None / 别的实例 —— 正是 'NoneType' has no attribute 'chat' 的成因")


def test_verifier_resolves_client_when_built_directly(llm_ready):
    """直接构造 LLMSecretVerifier 且不给 client 时，也要自己惰性解析。"""
    verifier = mod.LLMSecretVerifier(None)
    assert verifier.client is llm_ready


def test_verifier_stays_none_when_llm_unavailable(monkeypatch):
    """没配模型时保持 None，由 _verify_with_llm 降级，不硬拗。"""
    monkeypatch.setattr(mod, "llm_available", lambda: False)

    def _boom():
        raise AssertionError("不该在 llm_available() 为 False 时去拿 client")

    monkeypatch.setattr(mod, "get_client", _boom)

    assert mod.LLMSecretVerifier(None).client is None
    assert mod.SensitiveInfoScanner().client is None


def test_verify_degrades_instead_of_retrying_when_client_missing(monkeypatch):
    """llm_available() 说 True 但 client 是 None 时：降级，不要重试三次。"""
    called = {"n": 0}

    def _boom(*args, **kwargs):
        called["n"] += 1
        raise AttributeError("'NoneType' object has no attribute 'chat'")

    monkeypatch.setattr(mod, "llm_available", lambda: True)
    monkeypatch.setattr(mod, "get_client", lambda: None)

    scanner = mod.SensitiveInfoScanner()
    scanner.llm_verifier.client = None          # 复现故障现场

    candidates = [{"id": 0, "value": "abc", "original_line": "var a = 'abc';",
                   "context": "", "callers": []}]
    out = scanner._verify_with_llm(candidates)

    assert out, "降级也要把候选交回给调用方，不能吞掉"
    assert out[0]["ai_verified"] is False, "没经过模型确认，必须明确标记"
    assert called["n"] == 0


def test_llm_call_failure_is_marked_unverified(monkeypatch):
    """模型调不通时，上游会把整批标成 is_secret=True / risk Med。

    JSAtlas 保留上游的取值，但必须补 `ai_verified=False` ——
    否则下游会当成"AI 已复核为 Medium 风险"，那是把失败伪装成结论。
    """
    monkeypatch.setattr(mod, "llm_available", lambda: True)

    class _BrokenClient:
        def chat(self, *args, **kwargs):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(mod, "get_client", lambda: _BrokenClient())

    scanner = mod.SensitiveInfoScanner()
    candidates = [{"id": 0, "value": "abc", "original_line": "var a = 'abc';",
                   "context": "", "callers": []}]
    out = scanner._verify_with_llm(candidates)

    assert out and out[0]["ai_verified"] is False, "失败批次不能被标成 AI 已复核"


def test_verify_really_calls_chat_when_client_present(llm_ready):
    """正面：client 正常时复核要走真实调用，不能被上一条降级逻辑挡住。"""
    scanner = mod.SensitiveInfoScanner()

    candidates = [{"id": 0, "value": "abc", "original_line": "var a = 'abc';",
                   "context": "", "callers": []}]
    scanner._verify_with_llm(candidates)

    assert llm_ready.calls >= 1, "client 明明可用，却没发出调用"
