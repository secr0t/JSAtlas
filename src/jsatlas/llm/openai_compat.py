"""OpenAI SDK 兼容层。

上游 `infra/ai_client.py` 直接 `from openai import OpenAI, ...`，缺了就 import 失败。

JSAtlas 把它声明为核心依赖（AI 是默认能力），但**加载时不强依赖**：装了用真的，
没装用会明确报错的桩。这样环境缺包时工具仍能启动并给出可操作的指引，
而不是在 import 阶段就崩掉。
"""

from __future__ import annotations

try:
    from openai import (  # type: ignore
        OpenAI,
        APIConnectionError,
        APIStatusError,
        RateLimitError,
        APITimeoutError,
    )

    OPENAI_AVAILABLE = True
except ImportError:  # pragma: no cover - 取决于运行环境
    OPENAI_AVAILABLE = False

    class _MissingOpenAIError(RuntimeError):
        pass

    class _Missing:  # noqa: D401 - 占位桩
        """未安装 openai 时的替身，实例化或调用即给出明确指引。"""

        _MSG = ("未安装 openai SDK：`pip install openai`。"
                "AI 是 JSAtlas 的默认能力，不装时密钥复核与参数 Level 2/3 会降级为确定性结果")

        def __init__(self, *args, **kwargs):
            raise _MissingOpenAIError(self._MSG)

    class OpenAI(_Missing):  # type: ignore
        pass

    class APIConnectionError(Exception):
        pass

    class APIStatusError(Exception):
        def __init__(self, *args, **kwargs):
            super().__init__(*args)
            self.status_code = 0

    class RateLimitError(Exception):
        pass

    class APITimeoutError(Exception):
        pass


__all__ = [
    "OPENAI_AVAILABLE",
    "OpenAI",
    "APIConnectionError",
    "APIStatusError",
    "RateLimitError",
    "APITimeoutError",
]
