"""文本与代码片段工具。"""

from __future__ import annotations

from typing import Optional

_SNIPPET_LIMIT = 400


def clamp(text: str, limit: int = _SNIPPET_LIMIT) -> str:
    """截断长文本并加省略标记，防止证据片段把输出撑爆。"""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[+{len(text) - limit} chars]"


def line_of(code_bytes: bytes, byte_offset: int) -> int:
    """字节偏移 → 1-based 行号。"""
    if byte_offset < 0:
        return 0
    if byte_offset > len(code_bytes):
        byte_offset = len(code_bytes)
    return code_bytes[:byte_offset].count(b"\n") + 1


def column_of(code_bytes: bytes, byte_offset: int) -> int:
    """字节偏移 → 0-based 列号。"""
    if byte_offset <= 0:
        return 0
    head = code_bytes[:byte_offset]
    last_nl = head.rfind(b"\n")
    return len(head) - last_nl - 1


def decode_slice(code_bytes: bytes, start: int, end: int) -> str:
    """安全地按字节区间取文本，任何异常都降级为空串而不是抛出。"""
    try:
        return code_bytes[start:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def snippet_around(code_bytes: bytes, start: int, end: int, limit: int = _SNIPPET_LIMIT) -> str:
    """取代码片段（用于证据的 snippet 字段）。"""
    return clamp(decode_slice(code_bytes, start, end), limit)


def normalize_path(value: str) -> str:
    """路径归一化：去首尾空白与引号，去掉尾部斜杠。

    只做保守归一化，不改写语义（不去 query、不去协议），
    因为 query 本身就是参数情报的一部分。
    """
    if not value:
        return ""
    v = value.strip()
    if len(v) >= 2 and v[0] in "\"'`" and v[-1] == v[0]:
        v = v[1:-1]
    if len(v) > 1 and v.endswith("/"):
        v = v.rstrip("/")
    return v


def is_probable_api_path(value: str) -> bool:
    """粗判一个字符串是否像 API 路径（而非 CSS 类名、hash、文件名等）。

    判据刻意保守：宁可多留候选交给下游，也不要在这一层静默丢掉攻击面。
    """
    if not value or len(value) < 2 or len(value) > 300:
        return False
    if value.startswith("#"):
        return False
    if "\n" in value or "\r" in value:
        return False
    return True
