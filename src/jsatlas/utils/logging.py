"""日志规范。

与上游 JScanner2 的 `logger.get_logger` 的区别（迁移时必须保持）：
* 不创建任何文件 handler —— 核心库不应因为被 import 就在 CWD 建 logs/ 目录；
* 不引入 config / 飞书等外部依赖 —— 不产生任何网络副作用；
* 不主动 addHandler。日志是否落地、落地到哪里由调用方（CLI / 宿主程序）决定。

本模块提供的 `get_logger()` 支持**无参调用**，用于承接上游 `get_logger()` 的
调用形态，使逐字迁移的模块无需改动调用点。
"""

from __future__ import annotations

import logging
from typing import Optional

_LOGGER_NAME = "jsatlas"
_ROOT = logging.getLogger(_LOGGER_NAME)

# 默认给一个 NullHandler，避免"No handlers could be found"噪音，
# 也避免在无宿主的库场景下把日志喷到 root logger。
if not _ROOT.handlers:
    _ROOT.addHandler(logging.NullHandler())


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """取得 jsatlas 命名空间下的 logger。

    name 为 None 或空时返回包根 logger —— 这是为上游 `get_logger()` 无参调用
    形态保留的兼容入口（见 `analyzers/context/context_extractor.py`）。
    """
    if not name:
        return _ROOT
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def configure_logging(level: int = logging.INFO, stream=None) -> None:
    """给 CLI 或宿主程序使用：挂一个 stream handler 到 jsatlas 根 logger。

    库代码默认不调用它。
    """
    for h in list(_ROOT.handlers):
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.NullHandler):
            _ROOT.removeHandler(h)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    _ROOT.addHandler(handler)
    _ROOT.setLevel(level)
