"""JSAtlas 基础数据模型。

对应 PROJECT_SPEC 第 4 节的 JSON 顶层结构：
target / surfaces / points / intelligence / relationships / evidence / statistics

JSON 输出形态见 `output/report.py` 与 `schemas/report-v1.schema.json`。

约定：
* 无法确认的关联**必须允许为空**，不允许为了填满结果而猜测；
* 每个实体都带 `source_id`，跨资源归并时不会串味；
* `evidence_ids` 指向 evidence 列表，构成"发现 → 依据"的可追溯链；
* 对外承诺的字段集中在 `output/report.py` 的编译逻辑里，改动那里才算改契约。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from jsatlas.models import ids
from jsatlas.parsing.location import SourceLocation

# 置信度取值域。分析器只能从这三个里选，不允许自定义措辞。
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# 攻击面类型
SURFACE_API_PATH = "api_path"
SURFACE_URL = "url"
SURFACE_BASE_URL = "base_url"
SURFACE_ENDPOINT = "endpoint"

# 参数位置类型
POINT_QUERY = "query"
POINT_PATH = "path"
POINT_BODY = "body"
POINT_HEADER = "header"
POINT_UNKNOWN = "unknown"

# 情报类别
INTEL_CREDENTIAL = "credential"
INTEL_INTERNAL_ADDRESS = "internal_address"
INTEL_CONFIG = "config"
INTEL_DEBUG = "debug"
INTEL_AUTH = "auth_hint"
INTEL_PII = "pii"
INTEL_ENDPOINT_HINT = "endpoint_hint"

# 检测器类型（确定性 vs AI 必须能区分开）
DETECTOR_REGEX = "regex"
DETECTOR_STATISTICAL = "statistical"
DETECTOR_AST = "ast"
DETECTOR_AI = "ai"


@dataclass
class Target:
    """被分析的资源。"""

    id: str
    input_type: str  # text | file | url
    origin: str = ""  # 文件路径或 URL；纯文本输入时为空
    size_bytes: int = 0
    content_sha256: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "input_type": self.input_type,
            "origin": self.origin,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "attributes": self.attributes,
        }


@dataclass
class Evidence:
    """一条证据：某个发现是从哪里、依据什么被提取出来的。"""

    id: str
    source_id: str
    extractor: str  # 产出它的分析器名
    basis: str  # 提取依据（人话，给排查用）
    location: Optional[SourceLocation] = None
    snippet: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "extractor": self.extractor,
            "basis": self.basis,
            "location": self.location.to_dict() if self.location else None,
            "snippet": self.snippet,
            "attributes": self.attributes,
        }


@dataclass
class Surface:
    """攻击面：API、Endpoint 或其他可识别的外部交互入口。"""

    id: str
    kind: str
    value: str
    method: Optional[str] = None
    source_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    location: Optional[SourceLocation] = None
    confidence: str = CONFIDENCE_MEDIUM
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "method": self.method,
            "source_id": self.source_id,
            "evidence_ids": list(self.evidence_ids),
            "location": self.location.to_dict() if self.location else None,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }


@dataclass
class Point:
    """参数或输入点。"""

    id: str
    name: str
    location_type: str = POINT_UNKNOWN
    surface_id: Optional[str] = None  # 归属不明时为 None —— 不猜
    value: Optional[str] = None
    expression: Optional[str] = None
    source_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    location: Optional[SourceLocation] = None
    param_score: Optional[int] = None
    confidence: str = CONFIDENCE_MEDIUM
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "location_type": self.location_type,
            "surface_id": self.surface_id,
            "value": self.value,
            "expression": self.expression,
            "source_id": self.source_id,
            "evidence_ids": list(self.evidence_ids),
            "location": self.location.to_dict() if self.location else None,
            "param_score": self.param_score,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }


@dataclass
class Intelligence:
    """安全情报：敏感信息与有助于后续测试的其他线索。"""

    id: str
    category: str
    sub_type: str
    value: str
    detector: str = DETECTOR_REGEX
    source_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    location: Optional[SourceLocation] = None
    confidence: str = CONFIDENCE_MEDIUM
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "sub_type": self.sub_type,
            "value": self.value,
            "detector": self.detector,
            "source_id": self.source_id,
            "evidence_ids": list(self.evidence_ids),
            "location": self.location.to_dict() if self.location else None,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }


@dataclass
class Relationship:
    """实体之间的显式关联。"""

    id: str
    type: str
    from_id: str
    to_id: str
    basis: str = ""
    confidence: str = CONFIDENCE_MEDIUM
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "from_id": self.from_id,
            "to_id": self.to_id,
            "basis": self.basis,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }


# 关系类型常量
REL_API_HAS_PARAM = "api_has_param"
REL_API_DEFINED_IN = "api_defined_in"
REL_API_CALLED_BY = "api_called_by"
REL_INTEL_NEAR_API = "intel_near_api"
REL_API_USES_BASE_URL = "api_uses_base_url"
REL_EVIDENCE_OF = "evidence_of"


@dataclass
class Statistics:
    """处理数量、错误、耗时与发现统计。"""

    duration_ms: int = 0
    parsed: bool = False
    analyzers: Dict[str, Any] = field(default_factory=dict)
    counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_ms": self.duration_ms,
            "parsed": self.parsed,
            "analyzers": self.analyzers,
            "counts": self.counts,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass
class AnalysisResult:
    """一次分析的完整结果（内部视图）。

    对外输出形态在 `output/report.py` 里编译 —— 那里才是唯一承诺给别人看的 JSON。
    这里保留全量数据只是为了让分析链路可调试、可回归，
    不要直接把本对象序列化当成品发出去。
    """

    target: Optional[Target] = None
    surfaces: List[Surface] = field(default_factory=list)
    points: List[Point] = field(default_factory=list)
    intelligence: List[Intelligence] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    statistics: Statistics = field(default_factory=Statistics)

    # ---- 便捷查询 ----
    def surface_by_id(self, surface_id: str) -> Optional[Surface]:
        for s in self.surfaces:
            if s.id == surface_id:
                return s
        return None

    def evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        for e in self.evidence:
            if e.id == evidence_id:
                return e
        return None


def build_target(
    content: str,
    input_type: str,
    origin: str = "",
    attributes: Optional[Dict[str, Any]] = None,
) -> Target:
    """按内容构造 Target（ID 由内容摘要派生，保证确定性）。"""
    import hashlib

    raw = content.encode("utf-8", errors="replace")
    sha = hashlib.sha256(raw).hexdigest()
    return Target(
        id=ids.source_id(sha, origin),
        input_type=input_type,
        origin=origin,
        size_bytes=len(raw),
        content_sha256=sha,
        attributes=attributes or {},
    )
