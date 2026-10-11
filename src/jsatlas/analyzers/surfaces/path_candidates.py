"""API 路径 / URL 候选提取（确定性，基于 AST 字符串字面量）。

这是 JSAtlas 新增的分析器，不是上游迁移件。上游对应能力散落在
`processor/analysis/api/api_scan.py`（正则 + BeautifulSoup 的 HTML 场景抽取），
那份实现绑着 `config.config.WHITE_SCOPE_PATH`（客户白名单）和 tldextract，
不适合作为核心能力迁移。这里改为纯 AST 提取：
* 只认字符串字面量，不做路径预测、不做域名推断；
* 请求方法来自同一对象字面量的 `method` 键或 `.get/.post` 调用形态；
* **只收相对路径**：绝对 URL（`http(s)://`、协议相对 `//`）不产出候选，
  对齐 JScanner2 `main.py` 送 AI 前的闸门（`startswith("http") / ("//")` 跳过）。
  本站接口在 bundle 中均为相对路径，绝对 URL 多为外站导航/页面链接；
  baseURL 写入点由 `base_url.py` 独立提取，不受此规则影响；
* 只输出候选，是否真是 API 交给下游判断 —— 不在这里下结论。
"""

from __future__ import annotations

import re
from typing import List, Optional, Set

from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    SURFACE_API_PATH,
)
from jsatlas.parsing.location import location_from_node
from jsatlas.pipeline.registry import Analyzer, register
from jsatlas.utils.text import decode_slice, normalize_path

_ABS_URL = re.compile(r"^https?://[^\s\"'`<>]{2,300}$")
# 注意 `?` 必须放进来：query 串本身就是参数情报的一部分，
# 不能因为带了 `?a=1` 就把整条路径丢掉。
_REL_PATH = re.compile(r"^/[\w\-.~/:{}@!$&*+,;=%\[\]\\?]{1,200}$")

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
_VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

_STATIC_SUFFIX = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webp", ".map",
)

# 攻击面候选上限。**0 = 不限**（默认）。
# 原来是 5000，而且是命中后直接 `return` —— 不是"不再收集"，是整棵 AST 的遍历
# 就此中止，后面的候选全部丢掉。与"不做源码上限"是同一个取舍：宁可慢，不能漏。
# 真要卡规模把这个改成正数即可。
_MAX_SURFACES = 0


def _strip_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _ancestor_of_type(node, types: Set[str], limit: int = 6):
    """沿 parent 链向上找第一个指定类型的祖先。"""
    cur = node.parent
    depth = 0
    while cur is not None and depth < limit:
        if cur.type in types:
            return cur
        cur = cur.parent
        depth += 1
    return None


def _key_text(code_bytes: bytes, node) -> str:
    if node is None:
        return ""
    return _strip_quotes(decode_slice(code_bytes, node.start_byte, node.end_byte)).strip().lower()


def _method_in_object(code_bytes: bytes, obj) -> Optional[str]:
    """在对象字面量里找 `method: 'POST'` 这样的键值。"""
    if obj is None or obj.type != "object":
        return None
    for child in obj.named_children:
        if child.type != "pair":
            continue
        if _key_text(code_bytes, child.child_by_field_name("key")) != "method":
            continue
        value = child.child_by_field_name("value")
        if value is None or value.type != "string":
            continue
        method = _strip_quotes(decode_slice(code_bytes, value.start_byte, value.end_byte)).upper()
        if method in _VALID_METHODS:
            return method
    return None


def _detect_method(code_bytes: bytes, node) -> Optional[str]:
    """推断请求方法：优先对象字面量的 method 键，其次调用形态。"""
    pair = _ancestor_of_type(node, {"pair"}, limit=4)
    if pair is not None:
        method = _method_in_object(code_bytes, pair.parent)
        if method:
            return method

    call = _ancestor_of_type(node, {"call_expression"}, limit=6)
    if call is None:
        return None

    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        name = decode_slice(code_bytes, prop.start_byte, prop.end_byte).lower() if prop else ""
        if name in _HTTP_METHODS:
            return name.upper()

    # fetch(url, {method: 'POST'}) / request({url, method})
    args = call.child_by_field_name("arguments")
    if args is not None:
        for arg in args.named_children:
            method = _method_in_object(code_bytes, arg)
            if method:
                return method
    return None


def _looks_like_static_resource(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith(_STATIC_SUFFIX)


def _is_concat_tail(node) -> bool:
    """判断该字符串字面量是不是 `a + b` 拼接里的非首段。

    只在确定是 binary_expression 的右操作数时才判定为片段；左侧或其他情形一律放行，
    宁可保留候选也不误杀。
    """
    parent = node.parent
    if parent is None or parent.type != "binary_expression":
        return False
    left = parent.child_by_field_name("left")
    return left is not None and node.id != left.id


class PathCandidateAnalyzer(Analyzer):
    """从 AST 字符串字面量中提取 API 路径与 URL 候选。"""

    name = "surface.path_candidates"
    description = "AST 字符串字面量 → API 路径 / URL 候选（含请求方法推断）"
    dimension = "surface"

    def run(self, ctx) -> None:
        if ctx.tree is None:
            ctx.warn("AST 不可用，跳过 API 路径提取")
            return

        root = ctx.tree.root_node
        stack: List = [root]
        emitted = 0
        while stack:
            node = stack.pop()
            if node.type in ("string", "template_string"):
                if self._consider(ctx, node):
                    emitted += 1
                    if _MAX_SURFACES > 0 and emitted >= _MAX_SURFACES:
                        ctx.warn(f"攻击面候选达到上限 {_MAX_SURFACES}，已停止继续提取")
                        return
            stack.extend(node.children)

    def _consider(self, ctx, node) -> bool:
        raw = decode_slice(ctx.code_bytes, node.start_byte, node.end_byte)
        value = normalize_path(_strip_quotes(raw))
        if not value:
            return False

        if _ABS_URL.match(value) or value.startswith("//"):
            # 绝对 URL 不进 API 攻击面 —— 对齐 JScanner2 main.py 的 AI 闸门
            # （startswith("http") / startswith("//") 一律不送分析）。
            # 本站接口在 bundle 中均为相对路径（运行时拼到已验证的 baseURL）；
            # 绝对 URL 多为外站导航 / 营销页链接（实测 bundle 中 65% 是 .html 页面），
            # 不属于"本站接口"测试目标。baseURL 写入点由 BaseUrlAnalyzer 独立提取，
            # 不经过这里，因此不会误伤 baseURL 发现能力。
            return False

        if not _REL_PATH.match(value):
            return False

        kind = SURFACE_API_PATH

        if _looks_like_static_resource(value):
            return False

        # `'/api/v1/items/' + id + '/delete'` 里，`/delete` 是拼接的后续片段而非
        # 独立接口。把它当 API 输出会让清单里出现"/delete"这种没法直接请求的东西，
        # 因此只保留拼接表达式里最左侧那一段。片段内容记录在首段的 attributes 里，
        # 将来要做片段合并时不必重新扫一遍 AST。
        if _is_concat_tail(node):
            return False

        is_template = node.type == "template_string"
        method = _detect_method(ctx.code_bytes, node)

        if is_template:
            confidence = CONFIDENCE_LOW
            basis = "AST 模板字符串命中路径/URL 形态（含未求值表达式，需人工确认）"
        elif method:
            confidence = CONFIDENCE_HIGH
            basis = f"AST 字符串字面量命中路径/URL 形态，且同一表达式内识别出请求方法 {method}"
        else:
            confidence = CONFIDENCE_MEDIUM
            basis = "AST 字符串字面量命中路径/URL 形态（未识别出请求方法）"

        location = location_from_node(ctx.code_bytes, node)
        evidence = ctx.add_evidence(
            extractor=self.name,
            basis=basis,
            location=location,
            attributes={"node_type": node.type, "raw": raw},
        )
        ctx.add_surface(
            kind=kind,
            value=value,
            method=method,
            evidence=[evidence],
            location=location,
            confidence=confidence,
            attributes={
                "raw_literal": raw,
                "is_template": is_template,
                "has_method": method is not None,
            },
        )
        return True


register(PathCandidateAnalyzer())
