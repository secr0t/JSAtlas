"""JScanner2 密钥 Orchestration 全链路（secrets 的主判定来源）。

这是把 JScanner2 `main.py -asia` 那条链路**整段搬过来**的结果，编排逻辑在
`analyzers/intelligence/upstream_secret_scanner.py`（逐字迁移自 `secret_scanner.py`）：

    remove_html_tags → format_code（jsbeautifier / prettier）
      → CodeLineFilter 行切片提取候选
      → AdvancedSecretFilter 熵+分词双特征打分过滤
      → SenInfoContextExtractor 补 AST 上下文与调用者
      → 按敏感词/熵优先级裁剪到 max_llm
      → LLMSecretVerifier 分批复核（每批 20 条）
      → 按原始行去重

与上游的差别只有两处，都是"入口/出口变了"带来的：
1. 上游是准备好了以后写 SQLite（`db.save_sensitive_info`），这里是**返回结构化结果**。
2. 上游没有配 Key 就不跑这条链路；这里默认跑确定性部分，
   把 LLM 复核降级为可选阶段 —— 没复核的候选会带 `ai_verified=False`，
   不会和模型确认过的结果混在一起。

上游的 `-asir`（正则）与 `-asia`（本链路）是两个独立开关、取并集。
JSAtlas 按项目决策**只保留 `-asia`**：正则那条链路已整体移除，
secrets 唯一来源就是这里的"熵/分词打分 → LLM 复核"。
"""

from __future__ import annotations

from jsatlas.analyzers.intelligence.upstream_secret_scanner import SensitiveInfoScanner
from jsatlas.models.entities import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DETECTOR_AI,
    DETECTOR_STATISTICAL,
    INTEL_CREDENTIAL,
)
from jsatlas.parsing.location import location_from_span
from jsatlas.pipeline.registry import Analyzer, register

# 这里原本有 `_MAX_TEXT_CHARS = 2_000_000` 的源码上限（理由是格式化开销不可控）。
# 按项目决策移除：不做源码字符上限。大 bundle 格式化确实慢，但那是耗时问题，
# 不是正确性问题 —— 跳过整条链路等于把最大的那批目标整体放弃。

# 原定义在已移除的 `upstream_regex`（正则链路）里，那条链路整体删除后
# 常量就地落在本模块 —— 值不变，仍与上游的风险等级口径一致。
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"

_RISK_CONFIDENCE = {
    "high": (RISK_HIGH, CONFIDENCE_HIGH),
    "medium": (RISK_MEDIUM, CONFIDENCE_MEDIUM),
    "low": (RISK_LOW, CONFIDENCE_LOW),
    "med": (RISK_MEDIUM, CONFIDENCE_MEDIUM),
}


def reset() -> None:
    """清空模块级去重集合，供测试隔离使用。"""
    import jsatlas.analyzers.intelligence.upstream_secret_scanner as mod

    mod._AI_CANDIDATE_DEDUP = None
    mod._OUTPUT_LINE_DEDUP = None


class UpstreamSecretAnalyzer(Analyzer):
    """跑 JScanner2 完整的密钥 Orchestration 链路。"""

    name = "intelligence.upstream_secret"
    description = "JScanner2 全链路：预处理→行切片→熵/分词打分→AST 上下文→LLM 复核"
    dimension = "intelligence"

    def run(self, ctx) -> None:
        text = ctx.text
        if not text:
            return

        # 同一次运行内不重复输出同一个值（正则链路已移除，这里只防自身重复）
        known = {item.value for item in ctx.intelligence.values()}

        try:
            scanner = SensitiveInfoScanner()
            # AI 默认开启：LLM 复核照常跑。取不到模型时 SensitiveInfoScanner
            # 自己降级（ai_verified=False），这里不需要再判断开关。
            scanner.use_llm = bool(getattr(ctx.options, "enable_ai", True))
            results = scanner.scan(text, (ctx.target.origin if ctx.target else ""))
        except Exception as exc:  # noqa: BLE001 - 单个分析器失败不能拖垮整条流水线
            ctx.warn(f"JScanner2 密钥全链路执行失败：{type(exc).__name__}: {exc}")
            return

        # 把规模写进统计：secrets 为空时，下游要能看出是"没有候选"还是
        # "候选被 AI 否掉了"，否则空列表无从解释。
        stats = getattr(scanner, "last_scan_stats", None) or {}
        ctx.analyzer_stats[self.name] = {
            "status": "ok",
            "candidates": stats.get("candidates", len(results)),
            "kept": stats.get("kept", len(results)),
            "ai_used": bool(stats.get("ai_used", False)),
        }

        for item in results:
            value = item.get("value", "")
            if not value or value in known:
                continue
            known.add(value)

            ai_verified = bool(item.get("ai_verified", True))
            if ai_verified:
                sub_type, risk, suggestion, confidence, detector = self._from_ai(item)
            else:
                sub_type, risk, suggestion, confidence, detector = self._without_ai(item)

            evidence = ctx.add_evidence(
                extractor=self.name,
                basis=self._basis(item, ai_verified),
                location=_locate(ctx, item.get("original_line") or value),
                attributes={
                    "method": "jscanner2.pipeline",
                    "ai_verified": ai_verified,
                    "confidence": item.get("confidence"),
                },
            )
            ctx.add_intelligence(
                category=INTEL_CREDENTIAL,
                sub_type=sub_type,
                value=value,
                detector=detector,
                evidence=[evidence],
                location=_locate(ctx, item.get("original_line") or value),
                confidence=confidence,
                attributes={
                    "risk_level": risk,
                    "test_suggestion": suggestion,
                    "method": "jscanner2.pipeline",
                    "ai_verified": ai_verified,
                    "source_line": item.get("original_line", ""),
                },
            )

    # --------------- 取值策略 ---------------
    @staticmethod
    def _from_ai(item) -> tuple:
        """模型复核过：上游的看法为准，包括它判定的类型与建议文案。"""
        sub_type = (item.get("secret_type") or "unknown").strip() or "unknown"
        risk = str(item.get("risk_level") or "Medium").strip()
        suggestion = (item.get("test_suggestion") or "").strip()
        confidence = item.get("confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        if confidence >= 0.8:
            conf = CONFIDENCE_HIGH
        elif confidence >= 0.5:
            conf = CONFIDENCE_MEDIUM
        else:
            conf = CONFIDENCE_LOW
        return sub_type, risk, suggestion, conf, DETECTOR_AI

    @staticmethod
    def _without_ai(item) -> tuple:
        """没配模型：只输出确定性部分，不用猜测去冒充模型的类型判断。"""
        return (
            "high_entropy_value",
            RISK_LOW,
            "仅通过 JScanner2 的熵/分词打分命中，未经 AI 复核类型；"
            "建议结合变量名与所在函数调用判断是否为有效凭证",
            CONFIDENCE_LOW,
            DETECTOR_STATISTICAL,
        )

    @staticmethod
    def _basis(item, ai_verified: bool) -> str:
        context = (item.get("context") or "").strip()
        callers = item.get("callers") or []
        parts = ["JScanner2 全链路命中：行内引号取值后熵/分词打分超过阈值"]
        if context:
            parts.append(f"声明上下文：{' '.join(context.split())[:160]}")
        if callers:
            parts.append(f"调用点 {len(callers)} 处")
        parts.append(
            "AI 已复核类型" if ai_verified
            else "AI 未参与（未配置 Key 或调用失败），仅确定性结果")
        return "；".join(parts)


def _locate(ctx, needle: str):
    """在源码中定位该串首次出现的位置；找不到就留空，不猜。"""
    if not needle:
        return None
    start_char = ctx.text.find(needle)
    if start_char < 0:
        return None
    start_byte = len(ctx.text[:start_char].encode("utf-8", errors="replace"))
    end_byte = start_byte + len(needle.encode("utf-8", errors="replace"))
    return location_from_span(ctx.code_bytes, start_byte, end_byte)


__all__ = ["UpstreamSecretAnalyzer", "reset"]


register(UpstreamSecretAnalyzer())
