"""显式参数提取（确定性）。

JSAtlas 新增。补充上游缺口：上游参数名是靠大模型从上下文里读出来的，
这里先把**不需要推理就能确定**的参数拿到手：
* query：`/api/x?page=1&size=20` 里的键；
* path：路径模板里的 `:id`、`{id}`、`${id}`；
* body：`{data: {a: 1}}` / `params: {...}` 这类对象字面量的键。

body 参数与 API 的归属关系靠**同一个外层函数**判定；判定不了就留空
（surface_id=None），不猜。
"""

from __future__ import annotations

import re
from typing import List, Optional, Set
from urllib.parse import parse_qsl

from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    POINT_BODY,
    POINT_PATH,
    POINT_QUERY,
    SURFACE_API_PATH,
    SURFACE_URL,
)
from jsatlas.parsing.location import location_from_span
from jsatlas.pipeline.registry import Analyzer, register
from jsatlas.utils.text import decode_slice

_DATA_KEYS = frozenset({"data", "params", "body", "query", "payload", "json", "form", "headers"})
_FUNCTION_TYPES = {
    "function_declaration", "function_expression",
    "arrow_function", "method_definition",
}
_QUERY_PARAM = re.compile(r"[?&]([A-Za-z_][\w.\-]*)\s*=")
_PATH_TEMPLATE = re.compile(r"[:{](\$?[A-Za-z_][\w.\-]*)}?")


def _strip_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text


# query 串里能被当成"确定值"的字符集：含空格、引号、拼接符或标识符的一律视为表达式
_PLAIN_LITERAL = re.compile(r"^[A-Za-z0-9_.\-]*$")


def plain_literal(raw: str) -> str:
    """把 query 里的原始值落成字面量字符串。

    `/x?keyword=' + kw + '&pageSize=20` 这种写法里，keyword 的值是表达式而非常量，
    这种情况返回空字符串 —— 输出成 `{"keyword": ""}` 而不是把半成品赋给用户。
    """
    if not raw:
        return ""
    text = raw.strip()
    if _PLAIN_LITERAL.match(text):
        return text
    return ""


def literal_value(node, code_bytes) -> str:
    """取 AST 字面量节点的常量值；非常量（变量、成员表达式、调用…）一律返回空字符串。"""
    if node is None:
        return ""
    kind = node.type
    text = decode_slice(code_bytes, node.start_byte, node.end_byte)
    if kind == "string":
        return _strip_quotes(text)
    if kind == "template_string":
        # 模板串里带插值就不再是常量，宁缺勿猜
        if "${" in text:
            return ""
        return text[1:-1] if len(text) >= 2 else ""
    if kind in ("number", "true", "false", "null", "undefined"):
        return text
    return ""


def _enclosing_function(node):
    cur = node.parent
    depth = 0
    while cur is not None and depth < 20:
        if cur.type in _FUNCTION_TYPES:
            return cur
        cur = cur.parent
        depth += 1
    return None


class ExplicitParamAnalyzer(Analyzer):
    name = "parameters.explicit_params"
    description = "从路径模板、query 串与请求体对象字面量中提取确定的参数名"
    dimension = "parameters"

    def run(self, ctx) -> None:
        if ctx.tree is None:
            ctx.warn("AST 不可用，跳过显式参数提取")
            return

        surfaces = [s for s in ctx.surfaces.values() if s.kind in (SURFACE_API_PATH, SURFACE_URL)]
        self._from_path_and_query(ctx, surfaces)
        self._from_body_objects(ctx, surfaces)

    # ---------------- query / path ----------------
    def _from_path_and_query(self, ctx, surfaces) -> None:
        for surface in surfaces:
            value = surface.value or ""

            if "?" in value:
                query_part = value.split("?", 1)[1]
                for key, raw_value in parse_qsl(query_part, keep_blank_values=True):
                    if not key:
                        continue
                    self._add(
                        ctx, surface, key, POINT_QUERY,
                        basis=f"API 路径 query 串中的参数名 `{key}`",
                        value=plain_literal(raw_value),
                    )

            for match in _PATH_TEMPLATE.finditer(value):
                name = match.group(1).lstrip("$")
                if not name or name.isdigit():
                    continue
                self._add(
                    ctx, surface, name, POINT_PATH,
                    basis=f"API 路径模板占位符 `{match.group(0)}`",
                )

            # 兜底：没有 parse_qsl 覆盖到的 `?a=` 形态（如带模板串）
            if "?" in value:
                for key in _QUERY_PARAM.findall(value):
                    if key:
                        self._add(
                            ctx, surface, key, POINT_QUERY,
                            basis=f"API 路径 query 串中的参数名 `{key}`（正则兜底）",
                        )

    # ---------------- body ----------------
    def _from_body_objects(self, ctx, surfaces) -> None:
        located = [s for s in surfaces if s.location]
        root = ctx.tree.root_node
        stack: List = [root]
        seen: Set[str] = set()

        while stack:
            node = stack.pop()
            if node.type == "pair":
                self._consider_pair(ctx, node, located, seen)
            stack.extend(node.children)

    def _consider_pair(self, ctx, node, surfaces, seen: Set[str]) -> None:
        key_node = node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if key_node is None or value_node is None or value_node.type != "object":
            return
        key = _strip_quotes(decode_slice(ctx.code_bytes, key_node.start_byte, key_node.end_byte)).lower()
        if key not in _DATA_KEYS:
            return

        owner = self._owner_surface(node, surfaces)
        for child in value_node.named_children:
            if child.type != "pair":
                continue
            child_key = child.child_by_field_name("key")
            if child_key is None:
                continue
            name = _strip_quotes(decode_slice(ctx.code_bytes, child_key.start_byte, child_key.end_byte))
            if not name or name in seen:
                continue
            seen.add(name)
            self._add(
                ctx, owner, name, POINT_BODY,
                basis=f"请求体对象 `{key}` 中的字面量键 `{name}`",
                location=location_from_span(ctx.code_bytes, child.start_byte, child.end_byte),
                value=literal_value(child.child_by_field_name("value"), ctx.code_bytes),
            )

    def _owner_surface(self, node, surfaces):
        """按"同一个外层函数"判定归属；判定不了返回 None。"""
        func = _enclosing_function(node)
        if func is None:
            return None
        for surface in surfaces:
            loc = surface.location
            if loc and func.start_byte <= loc.start_byte and loc.end_byte <= func.end_byte:
                return surface
        return None

    # ---------------- 登记 ----------------
    def _add(self, ctx, surface, name, location_type, basis, location=None,
             value: str = "") -> None:
        evidence = ctx.add_evidence(
            extractor=self.name,
            basis=basis,
            location=location,
            attributes={"surface_id": surface.id if surface else None},
        )
        ctx.add_point(
            name=name,
            location_type=location_type,
            surface=surface,
            value=value,
            evidence=[evidence],
            location=location,
            confidence=CONFIDENCE_HIGH if surface else CONFIDENCE_MEDIUM,
            attributes={"association": "confirmed" if surface else "unknown"},
        )


register(ExplicitParamAnalyzer())
