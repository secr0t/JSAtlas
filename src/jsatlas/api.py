"""JSAtlas 对外 Python API。

核心接口可独立调用（PROJECT_SPEC 8）：下面的每个函数都不要求
"先启动一次完整扫描" —— 想单测某个分析器就用 `analyze_text(..., analyzers=[...])`。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# 导入分析器包以完成注册（副作用：填充注册表）
import jsatlas.analyzers  # noqa: F401
from jsatlas.inputs.remote import FetchError, FetchPolicy, from_url, from_urls
from jsatlas.inputs.source import Source, from_file, from_text
from jsatlas.models.entities import AnalysisResult
from jsatlas.output.report import build_report, merge_reports
from jsatlas.output.serializer import to_json, write_json
from jsatlas.output.validator import validate
from jsatlas.pipeline.context import AnalysisOptions
from jsatlas.pipeline.orchestrator import analyze as _analyze
from jsatlas.pipeline.registry import all_analyzers

__all__ = [
    "analyze_text",
    "analyze_file",
    "analyze_url",
    "analyze_urls",
    "analyze_source",
    "to_json",
    "report",
    "report_all",
    "write_json",
    "validate",
    "available_analyzers",
    "AnalysisOptions",
    "AnalysisResult",
    "FetchPolicy",
    "FetchError",
]


def analyze_text(
    code: str,
    *,
    origin: str = "",
    options: Optional[AnalysisOptions] = None,
) -> AnalysisResult:
    """分析一段 JavaScript 源码文本。"""
    return _analyze(code, input_type="text", origin=origin, options=options)


def analyze_file(path: str, *, options: Optional[AnalysisOptions] = None) -> AnalysisResult:
    """分析一个本地 JavaScript 文件。"""
    source = from_file(path)
    return analyze_source(source, options=options)


def analyze_url(
    url: str,
    *,
    policy: Optional[FetchPolicy] = None,
    options: Optional[AnalysisOptions] = None,
) -> AnalysisResult:
    """从远程 URL 获取一份 JavaScript 并分析。

    只会对这个 URL 发起一次 GET。分析过程中提取出的 API 不会被请求。
    拿不到资源时抛 `FetchError`，不返回"看起来什么都没有"的空结果。
    """
    source = from_url(url, policy)
    return analyze_source(source, options=options)


def analyze_urls(
    urls: List[str],
    *,
    policy: Optional[FetchPolicy] = None,
    options: Optional[AnalysisOptions] = None,
    max_workers: int = 4,
) -> List[AnalysisResult]:
    """并发分析多个 URL。单个失败不中断整体，错误进 `statistics.errors`。"""
    sources = from_urls(urls, policy=policy, max_workers=max_workers)
    return [analyze_source(s, options=options) for s in sources]


def analyze_source(source: Source, *, options: Optional[AnalysisOptions] = None) -> AnalysisResult:
    """分析一个已加载的 Source（本地文件、文本或远程资源的统一入口）。"""
    options = options or AnalysisOptions()
    result = _analyze(
        source.text,
        input_type=source.input_type,
        origin=source.origin,
        options=options,
    )
    if source.truncated:
        result.statistics.warnings.append("源码超过大小上限，已被截断分析")
    if source.error:
        result.statistics.errors.append(f"资源获取失败：{source.error}")

    result.target.attributes.setdefault("encoding", source.encoding)
    for key, value in (source.attributes or {}).items():
        result.target.attributes.setdefault(key, value)
    if source.attributes.get("content_type_unexpected"):
        result.statistics.warnings.append(
            f"响应 content-type 为 {source.attributes.get('content_type')}，"
            "看起来不是 JavaScript，结果可能无意义"
        )
    return result


def available_analyzers() -> List[Dict[str, Any]]:
    """列出已注册的分析器，便于按需挑选。"""
    return [
        {"name": a.name, "description": a.description, "dimension": a.dimension}
        for a in all_analyzers()
    ]


def report(result: AnalysisResult) -> Dict[str, Any]:
    """把单个分析结果编译成对外报告 —— `{"apis": [...], "secrets": [...]}`。"""
    return build_report(result)


def report_all(results: List[AnalysisResult]) -> Dict[str, Any]:
    """多个资源合成一份报告（每项自带 source，可以各自回溯出处）。"""
    return merge_reports(results)


def analyze_and_validate(
    code: str,
    *,
    origin: str = "",
    options: Optional[AnalysisOptions] = None,
) -> Dict[str, Any]:
    """分析并立即做结构/Schema 校验。

    返回 `{"result": 报告 dict, "ok": bool, "errors": [...], "mode": "..."}`，
    给不确定自己有没有装 jsonschema 的调用方一个省事的入口。
    """
    result = analyze_text(code, origin=origin, options=options)
    data = build_report(result)
    ok, errors, mode = validate(data)
    return {"result": data, "ok": ok, "errors": errors, "mode": mode}
