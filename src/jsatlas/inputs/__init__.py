"""输入适配层。

`source` 是核心（无网络依赖），`remote` 是可选适配器（只在真正取 URL 时
才 import HTTP 客户端，因此本包的导入本身不引入网络依赖）。
"""

from jsatlas.inputs.source import (  # noqa: F401
    INPUT_TYPES,
    MAX_SOURCE_BYTES,
    Source,
    decode_bytes,
    from_file,
    from_text,
)
from jsatlas.inputs.remote import (  # noqa: F401
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_READ_TIMEOUT,
    FetchError,
    FetchPolicy,
    from_url,
    from_urls,
    is_url,
)

__all__ = [
    "INPUT_TYPES",
    "MAX_SOURCE_BYTES",
    "Source",
    "decode_bytes",
    "from_file",
    "from_text",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_READ_TIMEOUT",
    "FetchError",
    "FetchPolicy",
    "from_url",
    "from_urls",
    "is_url",
]
