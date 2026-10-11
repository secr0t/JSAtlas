"""统计学敏感信息评分（迁移自 JScanner2 `secret_scanner.py` 的核心打分链路）。

迁移范围：`CodeLineFilter` + `SecretMathScorer` + `AdvancedSecretFilter` 三个类。

上游 `secret_scanner.py` 全链路里，这一段是**纯确定性**的：
行切片 → 引号内容提取 → 上下文/值过滤 → 熵(E) 与"像不像英文单词"(P) 双特征打分。
它不需要网络、不需要数据库、不需要大模型，因此是最值得迁移的一块。

相对上游的行为变化（已在 docs/migration-map.md 记录）：
1. **不再自动下载 NLTK 语料**。上游 `_init_nltk_offline()` 在语料缺失时会
   `nltk.download()` 联网。JSAtlas 的核心分析不允许有网络副作用，
   改为"取不到就用内置技术词表"，并向调用方发一条 warning。
2. 不再依赖 Bloom 落盘缓存、不再写 SQLite、不再调 watchdog —— 那是调度层的职责。
3. 打分公式、阈值、权重与上游**逐字一致**，未做任何调参。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from jsatlas.analyzers.intelligence.constants import (
    EXCLUDED_CONTEXT_PATTERNS,
    EXCLUDED_LITERAL_VALUES,
    HTTPX_STATIC_EXTENSIONS,
    SENSITIVE_KEYWORD_SET,
    SECRET_DETECTION_BLACKLIST,
    WEB_TECHNICAL_WORDS,
)
from jsatlas.utils.logging import get_logger

logger = get_logger("analyzers.intelligence.secret_scoring")

_DICTIONARY: Optional[Set[str]] = None
_DICTIONARY_SOURCE = ""


def _load_dictionary() -> Tuple[Set[str], str]:
    """加载"正常英文单词"词典，用于计算 P 特征。

    优先 NLTK words 语料；取不到就退回内置技术词表。
    与上游不同：这里**不会**联网下载语料。
    """
    global _DICTIONARY, _DICTIONARY_SOURCE
    if _DICTIONARY is not None:
        return _DICTIONARY, _DICTIONARY_SOURCE

    try:
        from nltk.corpus import words  # type: ignore

        loaded = set(w.lower() for w in words.words())
        if loaded:
            _DICTIONARY = loaded.union(WEB_TECHNICAL_WORDS)
            _DICTIONARY_SOURCE = "nltk:words+builtin"
            return _DICTIONARY, _DICTIONARY_SOURCE
    except Exception as e:  # noqa: BLE001
        logger.warning("NLTK words 语料不可用（%s），退回内置技术词表，P 特征精度会下降", e)

    _DICTIONARY = set(WEB_TECHNICAL_WORDS)
    _DICTIONARY_SOURCE = "builtin"
    return _DICTIONARY, _DICTIONARY_SOURCE


def dictionary_source() -> str:
    """当前词典来源，写进输出，便于下游判断结果可信度。"""
    _, source = _load_dictionary()
    return source


class CodeLineFilter:
    """逐行提取引号内的候选字符串，并用上下文黑名单做初筛。

    迁移自 JScanner2 `secret_scanner.CodeLineFilter`，逻辑未改。
    """

    def __init__(
        self,
        min_string_length: int = 5,
        min_sensitive_length: int = 5,
        max_string_length: int = 1000,
        blacklist: Optional[List[str]] = None,
    ):
        self.min_string_length = min_string_length
        self.min_sensitive_length = min_sensitive_length
        self.max_string_length = max_string_length

        combined = list(SECRET_DETECTION_BLACKLIST)
        if blacklist:
            combined.extend(blacklist)
        self.blacklist = set(combined)
        self.blacklist_pattern = (
            re.compile("|".join(re.escape(i) for i in self.blacklist), re.IGNORECASE)
            if self.blacklist else None
        )
        self.static_resource_extensions = tuple(HTTPX_STATIC_EXTENSIONS)
        self.sensitive_keywords = set(SENSITIVE_KEYWORD_SET)
        self.excluded_contexts = set(EXCLUDED_CONTEXT_PATTERNS)

    def extract_candidates(self, js_code: str) -> List[Tuple[str, str]]:
        quote_pattern = re.compile(r'(["\'])(.*?)\1')
        if not js_code:
            return []
        candidates = set()
        for line in js_code.splitlines():
            original_line = line.strip()
            if not original_line or len(original_line) > 3500:
                continue
            if '"' not in original_line and "'" not in original_line:
                continue

            line_lower = original_line.lower()
            is_bad_context = any(ctx in line_lower for ctx in self.excluded_contexts)
            has_sensitive_keyword = any(kw in line_lower for kw in self.sensitive_keywords)
            if is_bad_context and not has_sensitive_keyword:
                continue

            for _, content in quote_pattern.findall(original_line):
                content = content.strip()
                if self._is_valid_content(content, original_line, has_sensitive_keyword):
                    candidates.add((content, original_line))
        return list(candidates)

    def _is_valid_content(self, content: str, original_line: str, has_sensitive_keyword: bool) -> bool:
        ignore_prefix = re.compile(
            r"^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-"
            r"|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)",
            re.IGNORECASE,
        )
        unicode_pattern = re.compile(r"(\\)+u[0-9a-fA-F]{4}")

        length = len(content)
        if length > self.max_string_length:
            return False
        if self.blacklist_pattern and self.blacklist_pattern.search(content):
            return False
        if content.lower().endswith(self.static_resource_extensions) and length < 50:
            return False

        non_ascii_ratio = sum(1 for c in content if ord(c) > 127) / length if length else 0
        if non_ascii_ratio > 0.15:
            return False
        if re.search(r"[\u4e00-\u9fff]{2,}", content):
            return False
        if content.startswith("#") and "-" in content:
            return False

        min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length
        if length < min_len:
            return False
        if ignore_prefix.match(content):
            return False
        if any(c in content for c in [" ", "<", ">", "\\", "__", "(", ")"]):
            return False

        special_count = sum(1 for c in content if not c.isalnum())
        if length and (special_count / length) > 0.2:
            return False
        if len(unicode_pattern.findall(content)) >= 3:
            return False
        if sum(1 for c in content if ord(c) > 127) > length * 0.3:
            return False
        if content in EXCLUDED_LITERAL_VALUES:
            return False
        if content.isdigit() and length < 8:
            return False

        if not has_sensitive_keyword:
            if not any(ch in original_line for ch in ["=", ":", "{", "(", ","]):
                return False
        return True


class SecretMathScorer:
    """熵(E) 与"可分词为真实单词的比例"(P) 双特征评分器。

    迁移自 JScanner2 `SecretMathScorer`（V6.0 极简双特征版），公式未改：
        score = sigmoid(3.5 * (0.85*E - 1.2*P - 0.45))
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or {"w_e": 0.85, "w_p": 1.2}
        self._cache: Dict[str, Dict[str, float]] = {}
        self.valid_words_set, self.dictionary_source = _load_dictionary()

    def _log2(self, x: float) -> float:
        return math.log2(x) if x > 0 else 0.0

    def calc_E(self, s: str) -> float:
        length = len(s)
        if length == 0:
            return 0.0
        counter = Counter(s)
        entropy = -sum((c / length) * self._log2(c / length) for c in counter.values())
        max_entropy = self._log2(min(length, len(counter)))
        e_raw = entropy / max_entropy if max_entropy > 0 else 0.0
        # Sigmoid 长度置信度：L=7 时≈0.4，L=12 时≈0.73，L=20 时≈0.95
        length_confidence = 1.0 / (1.0 + math.exp(-0.3 * (length - 12)))
        return e_raw * length_confidence

    @staticmethod
    def _camel_split(s: str) -> List[str]:
        return [p for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", s) if p]

    @staticmethod
    def _wordninja_split(s: str) -> List[str]:
        try:
            import wordninja  # type: ignore

            return wordninja.split(s)
        except Exception:  # noqa: BLE001
            return []

    def calc_P(self, s: str) -> float:
        alpha_only = re.sub(r"[^a-zA-Z]", "", s).lower()
        length_alpha = len(alpha_only)
        if length_alpha < 4:
            return 0.0

        merged = set(self._wordninja_split(alpha_only) + self._camel_split(alpha_only))
        valid = [w for w in merged if len(w) > 3]
        matched_len = sum(len(w) for w in valid if w.lower() in self.valid_words_set)
        return min(matched_len / length_alpha, 1.0)

    def score(self, s: str) -> Dict[str, float]:
        if s in self._cache:
            return self._cache[s]
        e = self.calc_E(s)
        p = self.calc_P(s)
        w = self.weights
        base = w["w_e"] * e - w["w_p"] * p
        final = 1.0 / (1.0 + math.exp(-3.5 * (base - 0.45)))
        result = {"score": final, "E": e, "P": p}
        self._cache[s] = result
        return result


class AdvancedSecretFilter:
    """把打分结果变成"是 / 不是敏感信息"的判断。

    迁移自 JScanner2 `AdvancedSecretFilter`，阈值与长度调节系数未改。
    """

    def __init__(self, threshold: float = 0.75, weights: Optional[Dict[str, float]] = None):
        self.threshold = threshold
        self.scorer = SecretMathScorer(weights)
        self.sensitive_keywords = set(SENSITIVE_KEYWORD_SET)

    def shannon_entropy(self, data: str) -> float:
        """归一化熵 × 比特数（与上游同名方法逐字一致）。

        ⚠️ 这个方法不能少：`upstream_secret_scanner._priority_sort` 用它给候选排序，
        候选数超过 `max_ast_analysis`(50) / `max_llm`(80) 时一定会走到。
        迁移时漏掉它的后果不是"排序差一点"，而是 AttributeError：
        AST 富化那次被 `except` 吞掉（上下文静默全空），第二次在 `scan()` 里
        没有 try 保护，异常一路抛到分析器 —— 整条密钥链路 fail，secrets 恒为 0。
        """
        return self.scorer.calc_E(data) * math.log2(len(data)) if len(data) > 0 else 0.0

    def is_secret(self, text: str) -> bool:
        if re.match(r"^\.{0,2}/[a-zA-Z0-9_./-]+$", text):
            return False
        if not text or len(text) <= 6:
            return False

        score = self.scorer.score(text)["score"]
        length = len(text)
        # 短值更容易是噪声，长值稍微放宽
        threshold = self.threshold * (0.9 if length < 16 else (1.1 if length > 100 else 1.0))

        if any(kw in text.lower() for kw in self.sensitive_keywords):
            score = min(score * 1.2, 1.0)
        return score >= threshold

    def debug(self, text: str) -> Dict[str, float]:
        return self.scorer.score(text)
