"""统一源码位置模型。

上游 JScanner2 里位置信息散落在多处（行号、字节区间、裸切片），
JSAtlas 统一成这一个结构，让 evidence 永远能指回源码。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from jsatlas.utils.text import clamp, column_of, decode_slice, line_of

_SNIPPET_LIMIT = 400


@dataclass
class SourceLocation:
    """源码位置。byte 区间是权威值，行列由 byte 推导，保证可回溯。"""

    start_byte: int
    end_byte: int
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "snippet": self.snippet,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SourceLocation":
        return SourceLocation(
            start_byte=int(data.get("start_byte", 0)),
            end_byte=int(data.get("end_byte", 0)),
            start_line=int(data.get("start_line", 0)),
            end_line=int(data.get("end_line", 0)),
            start_column=int(data.get("start_column", 0)),
            end_column=int(data.get("end_column", 0)),
            snippet=data.get("snippet", ""),
        )

    def __str__(self) -> str:
        if self.start_line and self.end_line:
            if self.start_line == self.end_line:
                return f"L{self.start_line}"
            return f"L{self.start_line}-L{self.end_line}"
        return f"bytes[{self.start_byte}:{self.end_byte}]"


def location_from_span(
    code_bytes: bytes,
    start_byte: int,
    end_byte: int,
    snippet_limit: int = _SNIPPET_LIMIT,
) -> SourceLocation:
    """按字节区间构造位置。"""
    start_byte = max(0, int(start_byte))
    end_byte = max(start_byte, int(end_byte))
    text = decode_slice(code_bytes, start_byte, end_byte)
    return SourceLocation(
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=line_of(code_bytes, start_byte),
        end_line=line_of(code_bytes, end_byte),
        start_column=column_of(code_bytes, start_byte),
        end_column=column_of(code_bytes, end_byte),
        snippet=clamp(text, snippet_limit),
    )


def location_from_node(
    code_bytes: bytes,
    node: Any,
    snippet_limit: int = _SNIPPET_LIMIT,
) -> Optional[SourceLocation]:
    """从 tree-sitter 节点构造位置；node 为空时返回 None。"""
    if node is None:
        return None
    return location_from_span(code_bytes, node.start_byte, node.end_byte, snippet_limit)
