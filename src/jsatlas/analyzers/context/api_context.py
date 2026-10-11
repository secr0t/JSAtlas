"""API 上下文恢复（迁移自 JScanner2 `processor/js/context/context_extractor.py`）。

这是 JSAtlas 第一批迁移里价值最高的一块：把"某个 API 字符串"还原成
"它定义在哪个函数里、这个函数被谁调用、有没有构造请求参数"。

迁移说明：
* `context_extractor.py` 与 `param_scoring.py` 逐字迁移，算法未改；
* 上游那份实现已在 `JScanner2/test/context_recall/` 做过 305/305 全样本对拍，
  本次迁移沿用同一套代码，回归基线见 `tests/regression/`；
* 上游 `param_score` 在 params_scan 里只透传未使用，JSAtlas 显式写进
  surface.attributes，并在输出里附人话解释。

已知限制（沿用上游，不擅自改算法）：
* API 匹配是子串包含，短路径串可能命中多处；
* 仅支持 JavaScript，不含 TS / JSX；
* caller 召回做了作用域绑定 + 实参元数过滤，webpack 打包产物上常为 0 条 —— 这是预期结果。
"""

from __future__ import annotations

from typing import List

from jsatlas.analyzers.context.context_extractor import extract_multiple_apis_from_raw_code
from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    REL_API_CALLED_BY,
    REL_API_DEFINED_IN,
    SURFACE_API_PATH,
    SURFACE_URL,
)
from jsatlas.pipeline.registry import Analyzer, register
from jsatlas.utils.text import clamp

# param_score 的人话解释（直接写进输出，避免下游对着数字猜含义）
PARAM_SCORE_MEANING = (
    "AST 参数构造信号评分：-1=找不到外层函数、无法判定（应放行）；"
    "0=函数体内未发现参数构造信号；>=1=发现参数构造信号，数值越大信号越强"
)

_MAX_CALLER_EVIDENCE = 5


class ApiContextAnalyzer(Analyzer):
    name = "context.api_context"
    description = "恢复 API 所在的 wrapper 函数、调用点与参数信号评分"
    dimension = "context"

    def run(self, ctx) -> None:
        if ctx.tree is None:
            ctx.warn("AST 不可用，跳过上下文恢复")
            return

        targets = [
            s for s in ctx.surfaces.values()
            if s.kind in (SURFACE_API_PATH, SURFACE_URL)
        ]
        if not targets:
            return

        # 0 / 负数 = 不限（默认）。设了正数才做截断。
        limit = int(ctx.options.max_context_targets)
        if limit > 0 and len(targets) > limit:
            ctx.warn(
                f"攻击面数量 {len(targets)} 超过上下文恢复上限 {limit}，"
                f"仅处理前 {limit} 个（按 ID 排序，保证可复现）"
            )
            targets = sorted(targets, key=lambda s: s.id)[:limit]

        # 同一路径在源码里出现 N 次就是 N 个 surface，但上下文是同一份。
        # 只对去重后的路径做一次提取（结果按 value 取回），避免把同样的活做 N 遍 ——
        # 这是纯优化：每个 surface 仍然各自得到自己的证据与关系，不丢任何东西。
        paths: List[str] = list(dict.fromkeys(s.value for s in targets))
        results = extract_multiple_apis_from_raw_code(ctx.text, paths)

        for surface in targets:
            data = results.get(surface.value)
            if not data or not data.get("found"):
                continue

            wrapper = data.get("wrapper_code") or ""
            callers = list(data.get("caller_codes") or [])
            score = data.get("param_score", 0)

            wrapper_evidence = ctx.add_evidence(
                extractor=self.name,
                basis="API 字符串所在的最小语义边界（函数/方法）切片 + 变量常量传播",
                snippet=clamp(wrapper, ctx.options.max_context_bytes),
                attributes={"param_score": score, "param_score_meaning": PARAM_SCORE_MEANING},
            )
            ctx.add_relationship(
                REL_API_DEFINED_IN,
                from_id=surface.id,
                to_id=wrapper_evidence.id,
                basis="API 定义位置：由 AST 语义边界切片确定",
                confidence=CONFIDENCE_HIGH,
            )

            for caller in callers[:_MAX_CALLER_EVIDENCE]:
                caller_evidence = ctx.add_evidence(
                    extractor=self.name,
                    basis="调用点：经绑定作用域 + 实参元数双重过滤后命中",
                    snippet=clamp(caller, ctx.options.max_context_bytes),
                )
                ctx.add_relationship(
                    REL_API_CALLED_BY,
                    from_id=surface.id,
                    to_id=caller_evidence.id,
                    basis="API 调用位置：作用域绑定 + 实参元数校验",
                    confidence=CONFIDENCE_MEDIUM,
                )

            if len(callers) > _MAX_CALLER_EVIDENCE:
                ctx.warn(
                    f"{surface.value} 的调用点 {len(callers)} 个，"
                    f"仅登记前 {_MAX_CALLER_EVIDENCE} 条证据"
                )

            surface.attributes.update({
                "param_score": score,
                "param_score_meaning": PARAM_SCORE_MEANING,
                "wrapper_code": wrapper,
                "caller_count": len(callers),
                "context_found": True,
            })


register(ApiContextAnalyzer())
