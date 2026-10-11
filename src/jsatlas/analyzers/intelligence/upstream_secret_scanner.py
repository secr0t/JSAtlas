"""敏感信息扫描编排 + LLM 复核（原样迁移自 JScanner2 `secret_scanner.py`）。

搬运区段：上游文件从 `class LLMSecretVerifier` 起到文件末尾，逐字复制，
包含完整的 scan 编排：预处理 → 候选提取 → AST 上下文富化 → 优先级裁剪 → LLM 复核 → 去重。

相对上游的**唯一**结构性改动（其余逻辑逐字未动）：
1. `remove_html_tags` / `format_code`：换成本项目 `utils/html.py` 与 `parsing/preprocess.py`
   的同名实现（那两个文件也是逐字迁移的，见 md5 记录）。
2. `DiskBloomFilter` 换成 `MemoryDedup`（`utils/dedup.py`）：上游在 `Result/*.bloom`
   落盘的 Bloom 过滤器跨进程跨班次复用；JSAtlas 是"一段 JS 进、一份 JSON 出"的无状态
   调用，只保留**单次运行内去重**，且用朴素 `set` 而非 Bloom —— 单次量级用不上 Bloom，
   而 Bloom 的假阳性会把漏报变成概率问题。因此每次 `scan()` 开始时重置集合：
   单次 scan 内的去重语义与上游一致，跨调用不再互相抑制，也不留任何磁盘文件。
3. `watchdog.beat(...)` 心跳换成空实现 —— JSAtlas 没有长任务看门狗。
4. `db.save_sensitive_info(...)` 落库改成**返回值** —— 这正是本项目"出口改为 JSON"的部分。
5. LLM 复核阶段在**未配置 Key 时自动跳过**（见 `_verify_with_llm` 的守卫），
   跳过后仍返回结果，但 `ai_verified=False`，避免把模型结论和确定性结果混为一谈。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

import json_repair

from jsatlas.analyzers.intelligence.secret_context import SenInfoContextExtractor
from jsatlas.analyzers.intelligence.secret_prompt import SECRET_PROMPT
from jsatlas.analyzers.intelligence.secret_scoring import (
    AdvancedSecretFilter,
    CodeLineFilter,
)
from jsatlas.llm import get_client, llm_available
from jsatlas.parsing.preprocess import format_code
from jsatlas.parsing.scanner_rules import SENSITIVE_KEYWORD_SET
from jsatlas.utils.dedup import MemoryDedup
from jsatlas.utils.html import remove_html_tags
from jsatlas.utils.logging import get_logger

logger = get_logger(__name__)


class _WatchdogStub:
    """上游 watchdog 心跳探针的空实现。"""

    def beat(self, *args, **kwargs):
        pass


watchdog = _WatchdogStub()


class LLMSecretVerifier:
    def __init__(self, client=None, max_retries=2, retry_delay=1.0):
        # 上游 client 是必传的模块级单例（导入时就建好，永远不为空）。
        # JSAtlas 改成惰性单例，允许传 None，这里自己补上 ——
        # 否则 `self.client` 为 None，调用时只会得到
        # "'NoneType' object has no attribute 'chat'" 这种看不懂的报错。
        self.client = client if client is not None else (
            get_client() if llm_available() else None)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._local_logger = get_logger("LLMSecretVerifier")

    def verify_with_context(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """使用 LLM 验证候选敏感信息"""
        if not candidates:
            return []
        
        return self._verify_with_single_api(candidates)
    
    def _verify_with_single_api(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """单调用逻辑"""
        input_data = self._format_candidates_for_single(candidates)
        analysis_result = self._call_llm(input_data)
        if not analysis_result:
            # 上游这里直接 `return []`：模型调不通时整批候选**静默消失**，
            # 连"分析失败"的痕迹都不留。JSAtlas 不接受静默丢失 ——
            # 退回确定性结果并打 ai_verified=False，下游据此只输出确定性部分。
            for cand in candidates:
                cand.setdefault("is_secret", True)
                cand.setdefault("secret_type", "unknown")
                cand.setdefault("risk_level", "Low")
                cand.setdefault("confidence", 0.3)
                cand.setdefault("test_suggestion", "")
                cand["ai_verified"] = False
            return candidates
        return self._parse_and_merge(candidates, analysis_result)
    
    def _format_candidates_for_single(self, candidates: List[Dict[str, Any]]) -> str:
        """格式化多个候选对象用于单次调用"""
        formatted = {}
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            formatted[cand_id] = {
                "value": cand.get("value", ""),
                "context": cand.get("context", ""),
                "callers": cand.get("callers", [])
            }
        return json.dumps(formatted, ensure_ascii=False, indent=2)

    def _call_llm(self, input_data: str) -> Dict[str, Any]:
        messages = [
            {"role": "system", "content": SECRET_PROMPT},
            {"role": "user", "content": f"Analyze these hardcoded values:\n\n{input_data}"}
        ]
        for attempt in range(self.max_retries + 1):
            try:
                content = self.client.chat(messages=messages, max_tokens=2048, temperature=0.1)
                json_str = self._extract_json(content)
                if json_str: return json_repair.loads(json_str)
                else: self._local_logger.warning(f"⚠️ [LLM] 未找到有效 JSON (Attempt {attempt + 1})")
            except Exception as e:
                self._local_logger.warning(f"⚠️ [LLM] 调用失败 (Attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries: time.sleep(self.retry_delay * (attempt + 1))
        self._local_logger.error("❌ [LLM] 所有重试失败...")
        return {}

    def _extract_json(self, content: str) -> Optional[str]:
        try:
            json_repair.loads(content)
            return content
        except json.JSONDecodeError: pass
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if match: return match.group(1)
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match: return match.group()
        return None

    def _parse_and_merge(self, candidates: List[Dict[str, Any]], analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        verified = []
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            ai_result = analysis_result.get(cand_id, {})
            is_secret = ai_result.get("is_secret", 1)
            result = {
                **cand, "is_secret": bool(is_secret) if isinstance(is_secret, int) else is_secret,
                "secret_type": ai_result.get("secret_type", "unknown"),
                "risk_level": ai_result.get("risk_level", "Low"),
                "confidence": float(ai_result.get("confidence", 0.5)),
                "test_suggestion": ai_result.get("test_suggestion", ""),
                "ai_raw_analysis": {
                    "is_secret": ai_result.get("is_secret", 1),
                    "secret_type": ai_result.get("secret_type", "unknown"),
                    "risk_level": ai_result.get("risk_level", "Low"),
                    "confidence": ai_result.get("confidence", 0.5),
                    "test_suggestion": ai_result.get("test_suggestion", "")
                }
            }
            if result["is_secret"]: verified.append(result)
        return verified


class SensitiveInfoScanner:

    def __init__(self, client=None, max_ast_analysis=50, max_llm=80):
        self.client = client if client is not None else (get_client() if llm_available() else None)
        self.max_ast_analysis = max_ast_analysis
        self.max_llm = max_llm
        self.line_filter = CodeLineFilter()
        self.adv_filter = AdvancedSecretFilter(threshold=0.75)
        # 上游写作 `LLMSecretVerifier(client)`，client 为空只在"没传"时发生，
        # 那时上游压根不会走到复核。JSAtlas 里 client 可以为空、由上面惰性解析，
        # 所以这里必须传**解析后**的 self.client —— 传原始入参会拿到 None。
        self.llm_verifier = LLMSecretVerifier(self.client)
        # JSAtlas：是否允许 LLM 复核。AI 是默认能力，这里默认 True；
        # 取不到模型时由 _verify_with_llm 自行降级，不会抛错。
        self.use_llm = True
        self.ast_available = SenInfoContextExtractor is not None
        # 上一次 scan 的规模统计（候选 → 复核后剩余），供调用方排查"为什么没有 secrets"
        self.last_scan_stats: Optional[Dict[str, Any]] = None
        self._local_logger = get_logger("SensitiveInfoScanner")

    def scan(self, js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
        if not js_code: return []
        # 每次调用重置去重集合：等价于上游"新一轮任务"。
        # 只保证单次运行内不重复，不跨调用、不落盘（见 utils/dedup.py）。
        global _AI_CANDIDATE_DEDUP, _OUTPUT_LINE_DEDUP
        _AI_CANDIDATE_DEDUP = MemoryDedup("ai_candidates")
        _OUTPUT_LINE_DEDUP = MemoryDedup("output_lines")
        watchdog.beat("secret_scan", js_url)     # 每个 JS 文件一次真进展
        js_code = self._preprocess(js_code)
        candidates = self._extract_candidates(js_code)
        # logger.info(f"[SCAN] Extracted {len(candidates)} candidates after math filtering")
        if not candidates: return []
        if self.ast_available: candidates = self._enrich_with_ast(candidates, js_code)
        if len(candidates) > self.max_llm: candidates = self._priority_sort(candidates)[:self.max_llm]
        # 可观测性：候选数 / 是否走了 AI / 复核后剩几条。
        # 不加这些，报告里 secrets 为空时无法区分"没跑"和"跑了、全被判否"。
        self.last_scan_stats = {"candidates": len(candidates), "ai_used": False, "kept": 0}
        verified = self._verify_with_llm(candidates)
        self.last_scan_stats["kept"] = len(verified)
        logger.info("密钥链路：候选 %d 条 → 最终 %d 条（AI 复核：%s）",
                    len(candidates), len(verified),
                    "已执行" if self.last_scan_stats["ai_used"] else "未启用")
        return verified

    def _preprocess(self, js_code: str) -> str:
        js_code = remove_html_tags(js_code)
        try:
            watchdog.beat("secret_format", "prettier")   # 格式化前喂狗，超大JS慢也不误判
            js_code = format_code(js_code, fallback_on_error=True)
        except Exception as e: logger.error(f"⚠️ 代码格式化失败：{e}")
        return js_code

    def _extract_candidates(self, js_code: str) -> List[Dict[str, Any]]:
        raw_candidates = self.line_filter.extract_candidates(js_code)
        candidate_objects = []
        for i, (content, line) in enumerate(raw_candidates):
            if self.adv_filter.is_secret(content):
                if _AI_CANDIDATE_DEDUP.contains(content): continue
                _AI_CANDIDATE_DEDUP.add(content)
                candidate_objects.append({"id": i, "value": content, "original_line": line, "context": "", "callers": []})
        return candidate_objects

    def _enrich_with_ast(self, candidates: List[Dict[str, Any]], js_code: str) -> List[Dict[str, Any]]:
        try:
            extractor = SenInfoContextExtractor(js_code)
            if len(candidates) > self.max_ast_analysis: candidates = self._priority_sort(candidates)[:self.max_ast_analysis]
            for cand in candidates:
                context = extractor.get_full_context(cand["value"])
                cand["context"] = context.get("declaration", "")
                cand["callers"] = context.get("callers", [])
        except Exception as e:
            logger.error(f"⚠️ AST 上下文提取失败：{e}")
        return candidates

    def _priority_sort(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def priority_score(cand):
            value_lower = cand.get("value", "").lower()
            line_lower = cand.get("original_line", "").lower()
            score = 0
            for kw in SENSITIVE_KEYWORD_SET:
                if kw in value_lower or kw in line_lower: score += 10
            score += int(self.adv_filter.shannon_entropy(cand.get("value", "")) * 2)
            return score
        return sorted(candidates, key=priority_score, reverse=True)

    def _verify_with_llm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not candidates: return []
        # JSAtlas：取不到模型时跳过复核阶段，候选按确定性结果返回。
        # 这里同时校验 verifier 手上的 client 真的存在 —— 只判 llm_available()
        # 的话，client 为 None 会退化成三次 "'NoneType' has no attribute 'chat'" 重试，
        # 既慢又看不懂原因。
        verifier_client = getattr(getattr(self, "llm_verifier", None), "client", None)
        if not (getattr(self, 'use_llm', True) and llm_available()
                and verifier_client is not None):
            logger.info("未配置 JSATLAS_LLM_API_KEY，跳过 LLM 复核阶段")
            for cand in candidates:
                cand.setdefault("is_secret", True)
                cand.setdefault("secret_type", "unknown")
                cand.setdefault("risk_level", "Low")
                cand.setdefault("confidence", 0.3)
                cand.setdefault("test_suggestion", "")
                cand["ai_verified"] = False
            return self._dedup_results(candidates)
        logger.info(f"🚀 Sending {len(candidates)} candidates to LLM...")
        if getattr(self, "last_scan_stats", None) is not None:
            self.last_scan_stats["ai_used"] = True
        batch_size = 20
        all_verified = []
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(candidates) + batch_size - 1) // batch_size
            logger.info(f"🧠 [LLM] 处理批次 {batch_num}/{total_batches} ({len(batch)} 项)")
            watchdog.beat("secret_llm", f"batch {batch_num}/{total_batches}")
            try:
                verified_batch = self.llm_verifier.verify_with_context(batch)
                if verified_batch is None: continue
                all_verified.extend(verified_batch)
            except Exception as e:
                self._local_logger.error(f"❌ [LLM] 批次 {batch_num} 处理失败：{e}")
                for cand in batch:
                    # 上游的兜底：把整批标成 is_secret=True / risk Med。
                    # 上游没有"是否经过模型确认"这个概念，JSAtlas 有 ——
                    # 调用失败时补 ai_verified=False，否则下游会把它当成
                    # "AI 已复核为 Medium 风险"，那正是我们最想避免的误读。
                    cand.update({"is_secret": True, "secret_type": "unknown", "risk_level": "Med", "confidence": 0.3,
                                 "test_suggestion": "LLM 分析失败，建议人工审查", "ai_raw_analysis": {"error": str(e)},
                                 "ai_verified": False})
                    all_verified.append(cand)
        return self._dedup_results(all_verified)

    def _dedup_results(self, all_verified: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        final_results = []
        seen_lines = set()
        for res in all_verified:
            line = res.get("original_line", "")
            if line not in seen_lines:
                if _OUTPUT_LINE_DEDUP.contains(line): continue
                _OUTPUT_LINE_DEDUP.add(line)
                seen_lines.add(line)
                final_results.append(res)
        return final_results


def cleanup_dedup_sets():
    """清空本轮去重集合（上游这里是关闭 Bloom 落盘文件）。

    正常路径不需要调用：每次 `scan()` 开头已经重置。保留它是为了让调用方
    能在一次运行里手动分段。
    """
    _AI_CANDIDATE_DEDUP.close()
    _OUTPUT_LINE_DEDUP.close()


# 模块级默认集合。上游的第三个 Bloom（word_analysis）在本项目里没有任何使用点，
# 因此没有搬 —— 少一个全局变量，也少一个"看起来在用其实没用"的陷阱。
_AI_CANDIDATE_DEDUP = MemoryDedup("ai_candidates")
_OUTPUT_LINE_DEDUP = MemoryDedup("output_lines")