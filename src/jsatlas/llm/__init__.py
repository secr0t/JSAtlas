"""大模型接入层（AI 是默认能力，不是可选开关）。

原样迁移自 JScanner2 `infra/ai_client.py`（调用形态、重试与故障转移逻辑均未改），
只把三处与上���工程绑定的地方换掉：单例改惰性、配置改配置文件、openai 缺失时不崩。

JSAtlas 的立场：**AI 是默认能力**，密钥 LLM 复核与参数 Level 2/3 默认都跑。
只有在取不到模型时，各分析器才降级成确定性结论，并打上
`ai_verified=False` / `ai_analyzed=False` 让两类结论可区分 —— 这是兜底，不是开关。
"""

from __future__ import annotations

from jsatlas.llm.openai_compat import OPENAI_AVAILABLE


def llm_available() -> bool:
    """是否具备调用模型的条件（SDK 装了 + Key 配了）。"""
    from jsatlas.llm.settings import API_KEY

    return OPENAI_AVAILABLE and bool(API_KEY)


def get_client():
    """取得 AIHubClient 单例；不可用时抛错，由调用方决定是否降级。"""
    from jsatlas.llm.client import get_client as _get

    if not llm_available():
        raise RuntimeError(
            "未配置大模型：设置环境变量 JSATLAS_LLM_API_KEY 并安装 openai 后重试")
    return _get()


__all__ = ["llm_available", "get_client", "OPENAI_AVAILABLE"]
