"""稳定 ID 规则。

设计目标：
* **确定性** —— 同一份输入 + 同一套分析器，跑两次得到完全相同的 ID。
  因此 ID 由内容派生，不使用 uuid、不使用内存计数器、不依赖 dict 遍历顺序。
* **可去重** —— 相同语义的发现会自然收敛到同一个 ID，聚合阶段据此合并。
* **可解释** —— 前缀标出实体类型，人眼能看出一条 ID 属于哪一类。

ID 一律取 SHA-1 前 12 位十六进制。SHA-1 仅用于标识与去重，不用于安全目的。
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

_SEP = "\x1f"
_LENGTH = 12

PREFIX_SOURCE = "src"
PREFIX_EVIDENCE = "evd"
PREFIX_SURFACE = "srf"
PREFIX_POINT = "pnt"
PREFIX_INTELLIGENCE = "itl"
PREFIX_RELATIONSHIP = "rel"


def _digest(parts: Iterable[Any]) -> str:
    payload = _SEP.join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()[:_LENGTH]


def source_id(content_sha256: str, origin: str = "") -> str:
    """资源 ID：由内容摘要派生，内容相同则 ID 相同。"""
    return f"{PREFIX_SOURCE}_{_digest((content_sha256, origin))}"


def evidence_id(
    source_id_: str,
    extractor: str,
    start_byte: Any,
    end_byte: Any,
    basis: str = "",
) -> str:
    """证据 ID：同一个分析器在同一位置、同一依据下只产生一条证据。"""
    return f"{PREFIX_EVIDENCE}_{_digest((source_id_, extractor, start_byte, end_byte, basis))}"


def surface_id(source_id_: str, kind: str, value: str, method: str = "") -> str:
    """攻击面 ID：同源、同类型、同值、同方法视为同一处攻击面。"""
    return f"{PREFIX_SURFACE}_{_digest((source_id_, kind, value, method))}"


def point_id(
    source_id_: str,
    surface_id_: str,
    location_type: str,
    name: str,
    expression: str = "",
) -> str:
    """参数/输入点 ID：归属到具体攻击面，未归属时 surface_id_ 传空串。"""
    return f"{PREFIX_POINT}_{_digest((source_id_, surface_id_, location_type, name, expression))}"


def intelligence_id(
    source_id_: str,
    category: str,
    sub_type: str,
    value: str,
    start_byte: Any = "",
) -> str:
    """情报 ID：同源、同类别、同子类型、同值视为同一条情报。"""
    return f"{PREFIX_INTELLIGENCE}_{_digest((source_id_, category, sub_type, value, start_byte))}"


def relationship_id(type_: str, from_id: str, to_id: str) -> str:
    """关系 ID：同一对实体之间的同一种关系只有一条。"""
    return f"{PREFIX_RELATIONSHIP}_{_digest((type_, from_id, to_id))}"
