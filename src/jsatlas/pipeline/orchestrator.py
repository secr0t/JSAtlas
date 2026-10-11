"""分析编排器：解析 → 各分析器 → 关系构建 → 聚合 → 统计。

编排器本身不含任何提取逻辑。它只负责：
1. 准备上下文（源码、AST、稳定 ID）；
2. 按注册顺序调用分析器，单个分析器抛错不影响其余分析器；
3. 调用关系构建器；
4. 汇总统计并返回 AnalysisResult。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jsatlas.models.entities import (
    AnalysisResult,
    Statistics,
    Target,
    build_target,
)
from jsatlas.parsing import parser as ts_parser
from jsatlas.pipeline.context import AnalysisContext, AnalysisOptions
from jsatlas.pipeline import registry
from jsatlas.pipeline.relationship import build_relationships
from jsatlas.utils.logging import get_logger

logger = get_logger("pipeline.orchestrator")

# 说明：这里必须是**当前真实注册的分析器名**。写成历史名字会被下面的
# `if n in available` 静默吞掉，退化成"靠兜底追加顺序运行"——结果侥幸正确，
# 但执行顺序不可控且与文档不一致。增删改分析器时同步改这里。
_DEFAULT_ORDER = [
    "surface.path_candidates",
    "surface.base_url",
    # intelligence.upstream_regex（正则密钥链路）已按项目决策移除，
    # secrets 只保留计算式来源（熵/分词打分 + LLM 复核）。
    "intelligence.upstream_secret",
    "context.api_context",
    "parameters.explicit_params",
    # 对应上游 -asia 链路，默认开启；取不到模型时自身降级返回，不会拖垮整条流水线
    "parameters.upstream_pipeline",
]


def _ordered_analyzers(options: AnalysisOptions) -> List[registry.Analyzer]:
    """按固定顺序取用分析器，保证输出稳定（不依赖 dict 遍历顺序）。"""
    available = {a.name: a for a in registry.all_analyzers()}
    if options.analyzers:
        names = [n for n in options.analyzers if n in available]
        unknown = [n for n in options.analyzers if n not in available]
        if unknown:
            logger.warning("未注册的分析器被忽略: %s", unknown)
    else:
        names = [n for n in _DEFAULT_ORDER if n in available]
        # 允许后来注册的分析器排在末尾，但顺序按注册序，保证确定性
        names += [a.name for a in registry.all_analyzers() if a.name not in names]
    return [available[n] for n in names]


def analyze(
    code: str,
    *,
    input_type: str = "text",
    origin: str = "",
    options: Optional[AnalysisOptions] = None,
    target: Optional[Target] = None,
) -> AnalysisResult:
    """对一段 JavaScript 源码执行完整分析。

    这是 CLI 与 Python API 共同的唯一入口。
    """
    options = options or AnalysisOptions()
    ctx = _prepare_context(code, input_type=input_type, origin=origin,
                           options=options, target=target)
    ctx.tick()
    _run_analyzers(ctx)
    build_relationships(ctx)
    return _finalize(ctx)


def _prepare_context(
    code: str,
    *,
    input_type: str,
    origin: str,
    options: AnalysisOptions,
    target: Optional[Target],
) -> AnalysisContext:
    if code is None:
        code = ""
    if target is None:
        target = build_target(code, input_type=input_type, origin=origin)
    code_bytes = code.encode("utf-8", errors="replace")

    tree = None
    if code_bytes.strip():
        tree = ts_parser.parse_bytes(code_bytes)
        if tree is None:
            err = ts_parser.parser_error()
            logger.warning("AST 解析不可用%s", f"：{err}" if err else "")
    return AnalysisContext(
        target=target,
        text=code,
        code_bytes=code_bytes,
        tree=tree,
        options=options,
    )


def _run_analyzers(ctx: AnalysisContext) -> None:
    for analyzer in _ordered_analyzers(ctx.options):
        if ctx.options.enable_ai is False and analyzer.dimension == "ai":
            continue
        try:
            analyzer.run(ctx)
            # 分析器自己写了明细统计就保留它的（比如密钥链路的候选/复核数），
            # 没有就只记一个 "ok"。
            ctx.analyzer_stats.setdefault(analyzer.name, "ok")
        except Exception as e:  # noqa: BLE001 - 单个分析器失败不拖垮整条流水线
            ctx.analyzer_stats[analyzer.name] = f"error: {e}"
            ctx.error(f"{analyzer.name}: {e}")
            logger.exception("分析器 %s 执行失败", analyzer.name)


def _finalize(ctx: AnalysisContext) -> AnalysisResult:
    counts = {
        "surfaces": len(ctx.surfaces),
        "points": len(ctx.points),
        "intelligence": len(ctx.intelligence),
        "relationships": len(ctx.relationships),
        "evidence": len(ctx.evidence),
    }
    stats = Statistics(
        duration_ms=ctx.elapsed_ms(),
        parsed=ctx.tree is not None,
        analyzers=dict(ctx.analyzer_stats),
        counts=counts,
        errors=list(ctx.errors),
        warnings=list(ctx.warnings),
    )
    if ctx.tree is None:
        stats.warnings.append("AST 不可用，仅执行了不依赖语法树的分析")
    elif _has_syntax_error(ctx.tree):
        # tree-sitter 是容错解析器，语法错误时仍会返回树，但 has_error 为 True。
        # 这种情况下 AST 是"部分可用"的，结果可信度下降，必须明确告知调用方。
        stats.warnings.append("源码存在语法错误，AST 为部分解析结果，提取结果可能不完整")
        stats.parsed = False

    return AnalysisResult(
        target=ctx.target,
        surfaces=_sorted_by_id(ctx.surfaces),
        points=_sorted_by_id(ctx.points),
        intelligence=_sorted_by_id(ctx.intelligence),
        relationships=_sorted_by_id(ctx.relationships),
        evidence=_sorted_by_id(ctx.evidence),
        statistics=stats,
    )


def _has_syntax_error(tree) -> bool:
    try:
        return bool(tree.root_node.has_error)
    except Exception:  # noqa: BLE001
        return False


def _sorted_by_id(mapping: Dict[str, Any]) -> List[Any]:
    """按 ID 排序输出，保证同一输入的输出逐字节稳定。"""
    return [mapping[k] for k in sorted(mapping)]
