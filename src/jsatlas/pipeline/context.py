"""分析上下文：分析器之间唯一的数据交换面。

设计要点：
* 分析器**不直接**往结果列表里 append，而是调用 add_xxx —— 由上下文负责
  稳定 ID 计算、去重合并和证据登记，避免每个分析器各写一套去重。
* 所有 add_xxx 都返回实体对象（含已生成的 id），分析器据此建关系。
* `tree` 可能为 None（语法错误或未装 tree-sitter），分析器必须容忍。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from jsatlas.models import ids
from jsatlas.models.entities import (
    CONFIDENCE_MEDIUM,
    Evidence,
    Intelligence,
    Point,
    Relationship,
    Surface,
    Target,
)
from jsatlas.parsing.location import SourceLocation

_VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass
class AnalysisOptions:
    """分析选项。

    AI 是默认能力（与 JScanner2 一致）：`enable_ai` 默认 True，密钥 LLM 复核与
    参数 Level 2/3 都会跑。只有在取不到模型时，各分析器才会自行降级成确定性结果，
    并打上 `ai_verified=False` / `ai_analyzed=False` 标记 —— 这是兜底，不是开关。
    """

    enable_ai: bool = True
    # 指定只跑这些分析器（按 name），为空表示跑全部已注册的
    analyzers: Optional[List[str]] = None
    # 单个 surface 保留的上下文字节上限（影响 wrapper/caller 切片大小）
    max_context_bytes: int = 5000
    # 是否输出证据片段
    with_snippets: bool = True
    # 情报与攻击面的邻近关联：0 表示关闭（不按行号猜测关联）
    proximity_link_lines: int = 0
    # 上下文恢复最多处理多少个 API。**0 = 不限**（默认）。
    # 上下文提取在大 bundle 上确实慢，但限流等于让尾部接口全部拿不到上下文，
    # 那是漏报而不是优化。真要卡耗时用这个字段自己设，默认不替用户做这个取舍。
    max_context_targets: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisContext:
    """一次分析的可变状态。"""

    target: Target
    text: str
    code_bytes: bytes
    tree: Any = None
    options: AnalysisOptions = field(default_factory=AnalysisOptions)

    surfaces: Dict[str, Surface] = field(default_factory=dict)
    points: Dict[str, Point] = field(default_factory=dict)
    intelligence: Dict[str, Intelligence] = field(default_factory=dict)
    evidence: Dict[str, Evidence] = field(default_factory=dict)
    relationships: Dict[str, Relationship] = field(default_factory=dict)

    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    analyzer_stats: Dict[str, Any] = field(default_factory=dict)

    _started_at: float = field(default=0.0, repr=False)

    # ---------------- 证据 ----------------
    def add_evidence(
        self,
        extractor: str,
        basis: str,
        location: Optional[SourceLocation] = None,
        snippet: str = "",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Evidence:
        """登记一条证据。相同（分析器 + 位置 + 依据）只保留一条。"""
        start = location.start_byte if location else ""
        end = location.end_byte if location else ""
        ev_id = ids.evidence_id(self.target.id, extractor, start, end, basis)
        existing = self.evidence.get(ev_id)
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            return existing

        if not self.options.with_snippets:
            snippet = ""
        elif not snippet and location:
            snippet = location.snippet

        ev = Evidence(
            id=ev_id,
            source_id=self.target.id,
            extractor=extractor,
            basis=basis,
            location=location,
            snippet=snippet,
            attributes=attributes or {},
        )
        self.evidence[ev_id] = ev
        return ev

    # ---------------- 攻击面 ----------------
    def add_surface(
        self,
        kind: str,
        value: str,
        method: Optional[str] = None,
        evidence: Optional[List[Evidence]] = None,
        location: Optional[SourceLocation] = None,
        confidence: str = CONFIDENCE_MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Surface:
        sf_id = ids.surface_id(self.target.id, kind, value, method or "")
        evidence_ids = [e.id for e in (evidence or [])]
        existing = self.surfaces.get(sf_id)
        if existing is not None:
            for eid in evidence_ids:
                if eid not in existing.evidence_ids:
                    existing.evidence_ids.append(eid)
            if attributes:
                existing.attributes.update(attributes)
            if existing.confidence != confidence:
                existing.confidence = _weaker(existing.confidence, confidence)
            return existing

        sf = Surface(
            id=sf_id,
            kind=kind,
            value=value,
            method=method,
            source_id=self.target.id,
            evidence_ids=evidence_ids,
            location=location,
            confidence=confidence if confidence in _VALID_CONFIDENCE else CONFIDENCE_MEDIUM,
            attributes=attributes or {},
        )
        self.surfaces[sf_id] = sf
        return sf

    # ---------------- 参数 / 输入点 ----------------
    def add_point(
        self,
        name: str,
        location_type: str,
        surface: Optional[Surface] = None,
        value: Optional[str] = None,
        expression: Optional[str] = None,
        evidence: Optional[List[Evidence]] = None,
        location: Optional[SourceLocation] = None,
        param_score: Optional[int] = None,
        confidence: str = CONFIDENCE_MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Point:
        pt_id = ids.point_id(
            self.target.id,
            surface.id if surface else "",
            location_type,
            name,
            expression or "",
        )
        evidence_ids = [e.id for e in (evidence or [])]
        existing = self.points.get(pt_id)
        if existing is not None:
            for eid in evidence_ids:
                if eid not in existing.evidence_ids:
                    existing.evidence_ids.append(eid)
            if attributes:
                existing.attributes.update(attributes)
            return existing

        pt = Point(
            id=pt_id,
            name=name,
            location_type=location_type,
            surface_id=surface.id if surface else None,
            value=value,
            expression=expression,
            source_id=self.target.id,
            evidence_ids=evidence_ids,
            location=location,
            param_score=param_score,
            confidence=confidence if confidence in _VALID_CONFIDENCE else CONFIDENCE_MEDIUM,
            attributes=attributes or {},
        )
        self.points[pt_id] = pt
        return pt

    # ---------------- 情报 ----------------
    def add_intelligence(
        self,
        category: str,
        sub_type: str,
        value: str,
        detector: str,
        evidence: Optional[List[Evidence]] = None,
        location: Optional[SourceLocation] = None,
        confidence: str = CONFIDENCE_MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Intelligence:
        start = location.start_byte if location else ""
        it_id = ids.intelligence_id(self.target.id, category, sub_type, value, start)
        evidence_ids = [e.id for e in (evidence or [])]
        existing = self.intelligence.get(it_id)
        if existing is not None:
            for eid in evidence_ids:
                if eid not in existing.evidence_ids:
                    existing.evidence_ids.append(eid)
            if attributes:
                existing.attributes.update(attributes)
            return existing

        it = Intelligence(
            id=it_id,
            category=category,
            sub_type=sub_type,
            value=value,
            detector=detector,
            source_id=self.target.id,
            evidence_ids=evidence_ids,
            location=location,
            confidence=confidence if confidence in _VALID_CONFIDENCE else CONFIDENCE_MEDIUM,
            attributes=attributes or {},
        )
        self.intelligence[it_id] = it
        return it

    # ---------------- 关系 ----------------
    def add_relationship(
        self,
        type_: str,
        from_id: str,
        to_id: str,
        basis: str = "",
        confidence: str = CONFIDENCE_MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Optional[Relationship]:
        """登记一条关系。两端任一为空时返回 None —— 不允许凭空建边。"""
        if not from_id or not to_id:
            return None
        rel_id = ids.relationship_id(type_, from_id, to_id)
        existing = self.relationships.get(rel_id)
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            return existing
        rel = Relationship(
            id=rel_id,
            type=type_,
            from_id=from_id,
            to_id=to_id,
            basis=basis,
            confidence=confidence if confidence in _VALID_CONFIDENCE else CONFIDENCE_MEDIUM,
            attributes=attributes or {},
        )
        self.relationships[rel_id] = rel
        return rel

    # ---------------- 辅助 ----------------
    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def tick(self) -> None:
        if not self._started_at:
            self._started_at = time.perf_counter()

    def elapsed_ms(self) -> int:
        if not self._started_at:
            return 0
        return int((time.perf_counter() - self._started_at) * 1000)

    def surfaces_of_kind(self, kind: str) -> List[Surface]:
        return [s for s in self.surfaces.values() if s.kind == kind]


def _weaker(a: str, b: str) -> str:
    """同一实体被两次标注不同置信度时，取更保守的那个。"""
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order.get(a, 1) <= order.get(b, 1) else b
