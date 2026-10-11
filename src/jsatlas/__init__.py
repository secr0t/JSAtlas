"""JSAtlas — JavaScript Security Intelligence Engine.

从 JavaScript 源码中提取攻击面、参数与输入点、安全情报，并以统一、
可追溯、机器可消费的结构化数据输出。

上游项目：JScanner2
核心约束：确定性分析优先，AI 作为默认启用的复核与参数识别层（取不到模型时降级并留标记）；
输出的是情报与依据，不是漏洞结论。
"""

__version__ = "0.1.0"

from jsatlas.models.entities import AnalysisResult  # noqa: F401
from jsatlas.api import analyze_text, analyze_file  # noqa: F401
from jsatlas.output.report import REPORT_VERSION as __report_version__  # noqa: F401

__all__ = ["__version__", "__report_version__", "analyze_text", "analyze_file", "AnalysisResult"]
