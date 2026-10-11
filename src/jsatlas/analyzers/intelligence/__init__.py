"""情报分析器。

secrets 的判定严格沿用 JScanner2 的计算式方法（`-asia` 链路）：

* `secret_scoring.py` —— 上游 `secret_scanner.py` 的 CodeLineFilter /
  SecretMathScorer / AdvancedSecretFilter，公式与阈值未改；
* `secret_prompt.py` —— 上游 `secret/prompt.py` 原样迁移（AI 复核提示词）；
* `secret_context.py` —— 上游 `js/context/secret_extractor.py` 原样迁移（AST 上下文）；
* `upstream_secret_scanner.py` —— 上游 `secret_scanner.py` 的 Orchestration 全链路;
* `upstream_secret.py` —— 把 Orchestration 全链路接进流水线。

上游的 `-asir` 正则链路（`secret_regex.py` / `upstream_regex.py`）本已逐字迁移，
**现已按项目决策整体移除**：它把语言包里的界面文案（"请输入密码"、"Login password"）
当成硬编码口令，43 条全部是误报。secrets 从此只有一个来源：
行切片 → 熵/分词打分 → AST 上下文 → LLM 复核。

JSAtlas 只补上游没有的元数据（类型、风险等级、建议文案、源码位置），
**不改动"算不算命中"的判定逻辑**。
"""

from jsatlas.analyzers.intelligence import (  # noqa: F401
    secret_context,
    secret_prompt,
    secret_scoring,
    upstream_secret,
    upstream_secret_scanner,
)

__all__ = [
    "secret_context",
    "secret_prompt",
    "secret_scoring",
    "upstream_secret",
    "upstream_secret_scanner",
]
