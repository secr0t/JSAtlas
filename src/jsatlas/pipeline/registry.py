"""分析器注册表。

核心接口可独立调用：注册/取用一个分析器不要求启动完整扫描流程。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

_ANALYZERS: Dict[str, "Analyzer"] = {}


class Analyzer:
    """分析器基类。

    约定：
    * `name` 必须稳定 —— 它写进 evidence.extractor，也写进 statistics；
    * `run` 内部不得发起网络请求、不得写数据库、不得依赖全局扫描状态；
    * `run` 必须容忍 `ctx.tree is None`（语法错误 / tree-sitter 不可用）。
    """

    name: str = "analyzer"
    description: str = ""
    # 归属维度，仅用于统计分组
    dimension: str = "misc"

    def run(self, ctx) -> None:  # noqa: ANN001 - ctx: AnalysisContext
        raise NotImplementedError


def register(analyzer: Analyzer) -> Analyzer:
    if not analyzer.name:
        raise ValueError("分析器必须声明 name")
    _ANALYZERS[analyzer.name] = analyzer
    return analyzer


def unregister(name: str) -> None:
    _ANALYZERS.pop(name, None)


def get(name: str) -> Optional[Analyzer]:
    return _ANALYZERS.get(name)


def all_analyzers() -> List[Analyzer]:
    """按注册顺序返回全部分析器。"""
    return list(_ANALYZERS.values())


def select(names: Optional[Iterable[str]] = None) -> List[Analyzer]:
    """按名字白名单挑选分析器；未提供名单时返回全部。"""
    if not names:
        return all_analyzers()
    wanted = list(names)
    picked = []
    for name in wanted:
        a = _ANALYZERS.get(name)
        if a is not None:
            picked.append(a)
    return picked


def clear() -> None:
    """清空注册表（测试用）。"""
    _ANALYZERS.clear()
