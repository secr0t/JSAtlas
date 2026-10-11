"""JScanner2 参数 Orchestration 全链路（apis 的主参数来源）。

这是把 JScanner2 `main.py` 里 `-asia` 那条 AI 产线**整段搬过来**的结果：

    scan_multiple_apis(js_code, api_paths, target_url)
      → Step 1  API Path 黑名单（scanner_rules.is_api_path_blacklisted）
      → Step 2  AST 上下文提取 + 上下文类型过滤（HTTP_REQUEST / ROUTER_ONLY / …）
      → Step 3  Level 2  判断"有没有参数" + 给出参数名线索
      → Step 4  Level 3  逐个参数分析取值
      → Step 5  统计

编排逻辑位于 `upstream_params.py`（逐字迁移自 `params_scan.py`）；
结果里的 `params` 是**字符串**，用同样逐字迁移来的
`utils/params_string.parse_params_string` 转成模板要的字典。

启用条件：对应上游 `-asia` 链路，默认**开**（AI 是本工具的默认能力）。
唯一会跳过的情况是取不到模型（未配置 `JSATLAS_LLM_API_KEY`）；
此时由确定性分析器 `parameters.explicit_params` 兜底产出参数。

注意 Step 1 的黑名单会滤掉一部分路径（例如 `/api/v1/order/create`
会被上游黑名单命中）。这是上游行为，本分析器**只做增量补充**，
不会因此删除别处已经提取到的 surface 或 point。
"""

from __future__ import annotations

from typing import List, Optional

from jsatlas.analyzers.parameters.upstream_params import AISecurityAuditor
from jsatlas.llm import llm_available
from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    POINT_QUERY,
    SURFACE_API_PATH,
    SURFACE_URL,
)
from jsatlas.pipeline.registry import Analyzer, register
from jsatlas.utils.html import remove_html_tags
from jsatlas.utils.params_string import parse_params_string

# 这里原本有 `_MAX_TEXT_CHARS = 2_000_000` 的源码上限（理由是 AST 上下文提取开销不可控）。
# 按项目决策移除：不做源码字符上限。

_API_KINDS = (SURFACE_API_PATH, SURFACE_URL)


class UpstreamParamAnalyzer(Analyzer):
    """跑 JScanner2 的参数 Orchestration 链路。"""

    name = "parameters.upstream_pipeline"
    description = "JScanner2 参数链路：黑名单→AST上下文→Level2 判定→Level3 取值（默认开启）"
    dimension = "parameters"

    def run(self, ctx) -> None:
        if not ctx.options.enable_ai:
            return  # 显式关掉 AI 时跳过（默认不会走到这里）
        if not llm_available():
            ctx.warn("未配置 JSATLAS_LLM_API_KEY，跳过 JScanner2 参数 Level 2/3 链路")
            return  # 没有模型就跑不了 Level 2/3，由确定性分析器兜底

        text = ctx.text
        if not text:
            return

        api_paths = self._collect_paths(ctx)
        if not api_paths:
            return

        auditor = AISecurityAuditor()
        try:
            results = auditor.scan_multiple_apis(
                js_code=remove_html_tags(text),
                api_paths=api_paths,
                target_url=_target_url(ctx),
            )
        except Exception as exc:  # noqa: BLE001 - 单个分析器失败不能拖垮整条流水线
            ctx.warn(f"JScanner2 参数 Orchestration 链路失败：{type(exc).__name__}: {exc}")
            return

        for _api, detail in (results or {}).items():
            if not detail:
                continue
            self._emit(ctx, detail)

    # ---------------- 内部 ----------------
    @staticmethod
    def _collect_paths(ctx) -> List[str]:
        seen, paths = set(), []
        for surface in ctx.surfaces.values():
            if surface.kind not in _API_KINDS:
                continue
            if surface.value in seen:
                continue
            seen.add(surface.value)
            paths.append(surface.value)
        return paths

    def _emit(self, ctx, detail: dict) -> None:
        path = detail.get("path") or ""
        params_raw = detail.get("params") or ""
        method = (detail.get("method") or "").strip()

        owner = self._surface_for(ctx, path)
        params_map = parse_params_string(params_raw)

        # 方法名：上游 Level 3 判出来的更可靠，回填到已存在的 attack surface
        if method and owner is not None and not owner.method:
            owner.method = method

        already = {p.name for p in ctx.points.values() if p.surface_id == (owner.id if owner else None)}
        for name, value in params_map.items():
            name = (name or "").strip()
            if not name or name in already:
                continue
            already.add(name)

            evidence = ctx.add_evidence(
                extractor=self.name,
                basis=f"JScanner2 Level 3 参数分析产出（原始串 `{params_raw[:120]}`）",
                attributes={"method": "jscanner2.params", "raw_params": params_raw[:500]},
            )
            point = ctx.add_point(
                name=name,
                location_type=POINT_QUERY,
                surface=owner,
                value="" if value is None else str(value),
                evidence=[evidence],
                confidence=CONFIDENCE_HIGH if owner else CONFIDENCE_MEDIUM,
                attributes={"association": "confirmed" if owner else "unknown",
                            "method": "jscanner2.params"},
            )
            # 同名点已存在时 add_point 返回旧对象并保留原值；
            # 确定性分析器留空的地方，用 Level 3 给出的值补上。
            text_value = "" if value is None else str(value)
            if text_value and not point.value:
                point.value = text_value

    @staticmethod
    def _surface_for(ctx, path: str) -> Optional[object]:
        for surface in ctx.surfaces.values():
            if surface.value == path:
                return surface
        return None


def _target_url(ctx) -> str:
    """上游 target_url 是种子站点地址，只有真 URL 输入才有意义。"""
    origin = (ctx.target.origin if ctx.target else "") or ""
    return origin if origin.startswith(("http://", "https://")) else ""


__all__ = ["UpstreamParamAnalyzer"]


register(UpstreamParamAnalyzer())
