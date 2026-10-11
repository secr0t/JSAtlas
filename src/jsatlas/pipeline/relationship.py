"""关系构建：把各分析器产出的孤立发现连成图。

原则（PROJECT_SPEC 4）：
* 关联必须**显式**且带依据；
* 无法确认的关联允许不存在 —— 这里不会产生"看起来应该有关"的边而不标注；
* 凡是启发式推断出来的边，confidence 一律标 low，并在 basis 里写明是推断。
"""

from __future__ import annotations

from typing import List

from jsatlas.models.entities import (
    CONFIDENCE_LOW,
    REL_API_USES_BASE_URL,
    REL_INTEL_NEAR_API,
    SURFACE_API_PATH,
    SURFACE_BASE_URL,
    Surface,
)
from jsatlas.pipeline.context import AnalysisContext
from jsatlas.utils.logging import get_logger

logger = get_logger("pipeline.relationship")


def build_relationships(ctx: AnalysisContext) -> None:
    """所有关系构建步骤的统一入口。"""
    _link_relative_api_to_base_url(ctx)
    if ctx.options.proximity_link_lines > 0:
        _link_intel_near_api(ctx)


def _link_relative_api_to_base_url(ctx: AnalysisContext) -> None:
    """相对路径 API 与同源码内 baseURL 写入点之间的推断性关联。

    只在"API 是相对路径 + 源码内确实存在 baseURL 写入点"时才连边，
    confidence 标 low：我们没有证明这个 API 真的用了那个 baseURL。
    """
    base_urls = ctx.surfaces_of_kind(SURFACE_BASE_URL)
    if not base_urls:
        return

    for surface in ctx.surfaces.values():
        if surface.kind != SURFACE_API_PATH:
            continue
        if surface.value.startswith(("http://", "https://", "//")):
            continue
        for base in base_urls:
            ctx.add_relationship(
                REL_API_USES_BASE_URL,
                from_id=surface.id,
                to_id=base.id,
                basis="该 API 为相对路径，且同一源码内存在 baseURL 写入点（推断，未证明实际拼接关系）",
                confidence=CONFIDENCE_LOW,
                attributes={"base_url": base.value},
            )


def _link_intel_near_api(ctx: AnalysisContext) -> None:
    """按行号邻近把情报关联到攻击面（默认关闭）。

    这是纯位置启发式：同一段代码里出现的敏感串很可能与该 API 有关，
    但 JSAtlas 不把它当作已证实的关系，因此 confidence 固定为 low。
    """
    max_distance = ctx.options.proximity_link_lines
    api_surfaces: List[Surface] = [
        s for s in ctx.surfaces.values()
        if s.kind in (SURFACE_API_PATH, SURFACE_BASE_URL) and s.location
    ]
    for intel in ctx.intelligence.values():
        if not intel.location:
            continue
        for surface in api_surfaces:
            distance = abs(intel.location.start_line - surface.location.start_line)
            if distance <= max_distance:
                ctx.add_relationship(
                    REL_INTEL_NEAR_API,
                    from_id=intel.id,
                    to_id=surface.id,
                    basis=f"情报与攻击面在同一源码内相距 {distance} 行（位置推断）",
                    confidence=CONFIDENCE_LOW,
                    attributes={"line_distance": distance},
                )
