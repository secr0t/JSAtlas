"""baseURL 写入点提取（迁移自 JScanner2）。

迁移来源：`processor/js/context/base_url_extractor.py`（254 行，逐字迁移后仅改 import）。

为什么纳入攻击面维度：
baseURL 决定了相对路径 API 的真实落点，是"攻击面拼图"里缺了就拼不完整的一块。
同时它也是一条环境配置情报，因此这里会同时产出一个 intelligence。

关于"解析到什么程度"：
* 上游只找写入点，把整条语句原样抛出（值常需运行时才能确定，上游不猜）。
* JSAtlas 保留这个克制，但不浪费眼前的信息：写入点里若是**字面量** URL，
  就把它解析出来作为 `value`（置信度 high）；解析不出（变量拼接、函数调用）
  才退回整条语句并标注 `note`，绝不猜值。
"""

from __future__ import annotations

import re

from jsatlas.analyzers.surfaces.base_url_extractor import find_base_url_definitions
from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    SURFACE_BASE_URL,
)
from jsatlas.pipeline.registry import Analyzer, register
from jsatlas.utils.text import clamp

# 单引号 / 双引号字符串字面量
_STRING_LITERAL = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")
# 像 URL 的东西：绝对地址、协议相对、或以斜杠开头的路径
_URLISH = re.compile(r"^(?:https?://|//|/)\S*$")


def _literal_url_of(code: str) -> "str | None":
    """从写入点语句里取出字面量 URL；取不到返回 None（调用方据此不猜）。"""
    for match in _STRING_LITERAL.finditer(code or ""):
        value = match.group(2).strip()
        if _URLISH.match(value):
            return value
    return None


class BaseUrlAnalyzer(Analyzer):
    name = "surface.base_url"
    description = "AST 定位 baseURL/apiBase 等配置写入点"
    dimension = "surface"

    def run(self, ctx) -> None:
        if ctx.tree is None:
            ctx.warn("AST 不可用，跳过 baseURL 提取")
            return

        candidates = find_base_url_definitions(ctx.code_bytes, ctx.tree, ctx.target.origin or "")
        for item in candidates or []:
            code = (item.get("code") or "").strip()
            if not code:
                continue
            def_type = item.get("type", "unknown")
            literal = _literal_url_of(code)

            if literal:
                value = literal
                confidence = CONFIDENCE_HIGH
                note = "写入点中解析出的字面量 URL"
                extra = {"raw_statement": code}
            else:
                value = code
                confidence = CONFIDENCE_MEDIUM
                note = "仅定位写入点，实际 URL 需运行时确定（未猜测）"
                extra = {}

            evidence = ctx.add_evidence(
                extractor=self.name,
                basis=f"AST 命中 baseURL 类属性的写入点（{def_type}）",
                snippet=clamp(code, 500),
                attributes={"definition_type": def_type},
            )
            ctx.add_surface(
                kind=SURFACE_BASE_URL,
                value=value,
                evidence=[evidence],
                confidence=confidence,
                attributes={"definition_type": def_type, "note": note, **extra},
            )


register(BaseUrlAnalyzer())
