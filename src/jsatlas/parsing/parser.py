"""tree-sitter JavaScript 解析器单例。

迁移来源：JScanner2 `processor/js/context/parse.py`（17 行）。

相对上游的三点改造：
1. 去掉 `from logger import get_logger` —— 上游这条 import 会牵出
   `config.config` → `infra.feishu`，导致 import 本模块即可能触发网络告警，
   并在 CWD 建 `logs/` 目录。JSAtlas 改用 `jsatlas.utils.logging`。
2. 初始化失败不再静默：`parser_error()` 可查询原因，调用方按需处理。
3. 提供 `set_parser()` 注入点，测试与多语言扩展不需要改全局单例的获取方式。
"""

from __future__ import annotations

import threading
from typing import Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser, Tree

from jsatlas.utils.logging import get_logger

logger = get_logger("parsing.parser")

_PARSER: Optional[Parser] = None
_INIT_ERROR: Optional[str] = None
_INJECTED = False
_LOCK = threading.Lock()


def _build() -> Parser:
    """构造 JavaScript 解析器。失败时抛异常，由 get_parser 转成可查询状态。"""
    try:
        language = Language(tree_sitter_javascript.language())
        return Parser(language)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"tree-sitter 初始化失败: {e}") from e


def get_parser() -> Optional[Parser]:
    """取得 JavaScript 解析器；未安装 tree-sitter 语法包时返回 None。"""
    global _PARSER, _INIT_ERROR, _INJECTED

    if _INJECTED:
        return _PARSER
    if _PARSER is not None or _INIT_ERROR is not None:
        return _PARSER

    with _LOCK:
        if _PARSER is None and _INIT_ERROR is None and not _INJECTED:
            try:
                _PARSER = _build()
            except Exception as e:  # noqa: BLE001
                _INIT_ERROR = str(e)
                logger.error("Tree-sitter 初始化失败: %s", e)
    return _PARSER


def parser_error() -> Optional[str]:
    """解析器初始化失败的原因；成功时为 None。"""
    get_parser()
    return _INIT_ERROR


def set_parser(parser: Optional[Parser]) -> None:
    """注入解析器（测试或多语言扩展用）。传 None 表示恢复内置单例。"""
    global _PARSER, _INJECTED, _INIT_ERROR
    with _LOCK:
        if parser is None:
            _INJECTED = False
            _INIT_ERROR = None
            _PARSER = None
        else:
            _INJECTED = True
            _PARSER = parser


def reset_parser() -> None:
    """丢弃已缓存的解析器（一般只在测试里用）。"""
    set_parser(None)


def parse_bytes(code_bytes: bytes) -> Optional[Tree]:
    """把源码字节解析成 AST；解析器不可用时返回 None（不抛异常）。"""
    parser = get_parser()
    if parser is None:
        return None
    try:
        return parser.parse(code_bytes)
    except Exception as e:  # noqa: BLE001
        logger.error("解析失败: %s", e)
        return None


def parse_text(code: str) -> Optional[Tree]:
    """把源码文本解析成 AST。"""
    return parse_bytes(code.encode("utf-8", errors="replace"))
