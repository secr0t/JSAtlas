"""上下文恢复分析器。

context_extractor.py 为上游 `processor/js/context/context_extractor.py` 的逐字迁移件。
"""

from jsatlas.analyzers.context import api_context  # noqa: F401

__all__ = ["api_context"]
