# JSAtlas ↔ JScanner2 一致性核对报告

**核对日期：** 2026-10-09
**核对对象：** secret 识别模块 / param 提取模块 / 提示词
**上游基准：** `C:\Users\Cheng\Desktop\JScanner2`
**核对方法：** 逐行源码比对 + 逐值对拍 + 受控变量实验

> **⚠️ 本报告第 0 节及后续判定已于同日被第二批迁移推翻，请勿直接引用结论。**
> 第二批迁移按「入口改 URL/代码/文件、出口改 JSON、中间逻辑不变」的目标，
> 把下面标为"缺失"的条目几乎全部按**逐字迁移**补上了。
> 最新状态见 **[第 9 节：第二轮核对结论](#9-第二轮核对结论第二批迁移后)**。
> 保留原始判定是为了留存"当时为什么不一致"的证据链，便于回溯。

---

## 0. 总判定（第二轮迁移**之前**的状态）

| 核对项 | 判定 | 一句话结论 |
| --- | --- | --- |
| secret 识别方式（正则链路） | ✅ **一致** | 逐值对拍集合相同，唯一差异是已记录的 K-10 收尾清理 |
| secret 识别方式（统计打分链路） | ⚠️ **核心算法一致，前置流程不一致** | 打分公式逐字迁移，但缺了格式化预处理，压缩 JS 上会漏 |
| secret AI 复核过程 | ❌ **完全缺失** | JSAtlas 全流程零 LLM 调用 |
| param 提取方式 | ❌ **方法根本不同** | 上游参数名**只来自 LLM**；JSAtlas 是 AST 确定性提取 |
| param 提取逻辑 | ⚠️ **部分一致** | `param_pre_filter` 逐字一致；三层漏斗、黑名单、路由过滤全缺 |
| param AI 参数识别过程 | ❌ **完全缺失** | Level 2 / Level 3 / 操作分类三层 LLM 均无 |
| API 修正 | ❌ **完全缺失** | 上游 BaseURL Agent + Prefix Agent，均未迁移 |
| 提示词 | ❌ **零迁移** | 上游 8 条 prompt，JSAtlas 一条都没有 |

**一句话总结：JSAtlas 迁移的是 JScanner2 的「确定性前半段」，它的「AI 后半段」整体没有过来。**
上游这三条能力恰好都是**"确定性只负责产出候选，最终判定和命名由 LLM 完成"**的结构，
所以"严格一致"这个标准目前在架构层面就达不成，需要你拍板补哪一段。

---

## 1. secret 识别模块

### 1.1 先纠正一个前提：上游有**两条独立开关**的密钥链路

`main.py:831-884` `_extract_sensitive_info()`：

```python
if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
    ai_results = self.sensitive_scanner.scan(js_code=..., js_url=url)   # 链路 A
    for item in ai_results: combined_sensitive_info.add(item.get("value", ""))
if self.args.analyzeSensitiveInfoRex:
    rex_results = find_all_info_by_rex(scan_info["source_code"])        # 链路 B
    combined_sensitive_info.update(rex_results)
```

JSAtlas 把两条都搬了，但**链路 A 只搬了中间两段**。

### 1.2 链路 A（AI）上游完整流程 —— `secret_scanner.py:378 scan()`

```
① _preprocess        remove_html_tags(js_code) → format_code(js_code, fallback_on_error=True)
② _extract_candidates line_filter.extract_candidates → adv_filter.is_secret → Bloom 全局去重
③ _enrich_with_ast   SenInfoContextExtractor(js_code).get_full_context(value) → cand.context / cand.callers
                     （>max_ast_analysis=50 时先 _priority_sort 截断）
④ 优先级截断         >max_llm=80 时 _priority_sort 取 Top80
⑤ _verify_with_llm   batch_size=20 分批 → LLMSecretVerifier.verify_with_context
⑥ 行级去重           _OUTPUT_LINE_DEDUP（Bloom）
⑦ 落库               db.save_sensitive_info(js_url, verified)
```

`LLMSecretVerifier` 关键参数（`secret_scanner.py:279-362`）：

| 项 | 值 |
| --- | --- |
| prompt | `SECRET_PROMPT`（`processor/analysis/secret/prompt.py`） |
| 输入格式 | `{cand_id: {value, context, callers}}`，`json.dumps(indent=2)` |
| user 消息 | `"Analyze these hardcoded values:\n\n{input_data}"` |
| 调用参数 | `max_tokens=2048, temperature=0.1` |
| 重试 | `max_retries=2`，`sleep(retry_delay * (attempt+1))`，`retry_delay=1.0` |
| JSON 提取 | `json_repair.loads(全文)` → ```` ```json ``` ```` 围栏 → 首个 `{...}` |
| 合并默认 | `is_secret=1`、`secret_type="unknown"`、`risk_level="Low"`、`confidence=0.5` |
| 输出类型枚举 | `license_key\|api_key\|token\|password\|endpoint\|other` |
| **保留条件** | `result["is_secret"]` 为真才入结果（L361） |

**LLM 失败时的降级（L449-452）**，这条很反直觉，必须照抄：

```python
cand.update({"is_secret": True, "secret_type": "unknown", "risk_level": "Med",
             "confidence": 0.3, "test_suggestion": "LLM 分析失败，建议人工审查"})
all_verified.append(cand)     # ← 失败 = 判定为密钥并保留，不是丢弃
```

### 1.3 逐项差异

| # | 环节 | 上游 | JSAtlas | 判定 |
| --- | --- | --- | --- | --- |
| S-01 | HTML 标签剥离 | `_preprocess`: `remove_html_tags`（`infra/utils.py:4`） | 无 | ❌ 缺失 |
| S-02 | **代码格式化** | `_preprocess`: `format_code`（jsbeautifier / prettier + 应急分行兜底） | 无 | ❌ **缺失，影响最大** |
| S-03 | 行切片 | 同阈值 `len(line.strip()) > 3500` 跳过 | 同阈值同上（逐字一致） | ✅ 一致 |
| S-04 | `CodeLineFilter.extract_candidates` | — | 逐字迁移 | ✅ 一致 |
| S-05 | `SecretMathScorer` / `AdvancedSecretFilter` | 公式 `1/(1+e^-3.5(base-0.45))`，`w_e=0.85,w_p=1.2`，`threshold=0.75`，长度调节 `0.9/1.0/1.1`，关键词提权 `×1.2` | 逐字迁移 | ✅ 一致 |
| S-06 | AST 上下文富化（`context`/`callers`） | `SenInfoContextExtractor.get_full_context` | 无 | ❌ 缺失 |
| S-07 | `_priority_sort` + 50/80 截断 | 有 | 无 | ❌ 缺失 |
| S-08 | **LLM 复核** | batch=20 / retries=2 / temp=0.1 / json_repair | **零 LLM 调用** | ❌ **完全缺失** |
| S-09 | LLM 失败降级（保留 + Med + 0.3） | 有 | 无 | ❌ 缺失 |
| S-10 | Bloom 跨文件去重 | `Result/ai_candidates.bloom` 等三个磁盘 Bloom | 单次运行内 `known` set | ⚠️ 跨批次行为不同 |
| S-11 | 行级输出去重 | `_OUTPUT_LINE_DEDUP` | 无 | ❌ 缺失 |
| S-12 | `secret_type` | LLM 给（6 类枚举） | 硬编码 `high_entropy_value` | ❌ 不等价 |
| S-13 | `risk_level` | LLM 给 `High/Med/Low` | JSAtlas 自定：score≥0.95→High，≥0.85→Medium，否则 Low | ❌ **算法不同** |
| S-14 | `test_suggestion` | LLM 生成 | JSAtlas 三段固定文案 | ❌ 不等价 |
| S-15 | JS 字符串收尾残渣清理 | 无（会输出 `...3306/prod?useSSL=false';`） | `strip_js_string_residue` | ⚠️ **有意偏离**，已记录为 K-10 |

### 1.4 实测：正则链路对拍

用 `importlib` 绕过上游 `__init__`（它会拖入 `openai`），直接加载原文件：

| 样本 | 上游 `find_all_info_by_rex` | JSAtlas 正则链路 | 差异 |
| --- | --- | --- | --- |
| `examples/input.js` | 3 条 | 3 条 | `jdbc:...?useSSL=false';` vs `jdbc:...?useSSL=false` —— 即 K-10 |
| `tests/fixtures/basic.js` | 3 条 | 3 条 | **0** |
| `tests/fixtures/scope_sample.js` | 0 条 | 0 条 | **0** |
| `tests/fixtures/syntax_error.js` | 0 条 | 0 条 | **0** |

**链路 B 通过，与上游逐值一致。**

### 1.5 实测：S-02 格式化缺失的影响（授控实验）

同一份 `CodeLineFilter` + `AdvancedSecretFilter`，变量只有"是否先展开"：

构造 minified 单行 JS（CDN 常见交付形态），内含一个形似高熵 token：

```
构造样本: 10,024 字符 > 3500 阈值
  A JSAtlas 现状（原始 minified，整行被跳过）: 0 条
  B 上游路径（先 jsbeautifier 展开）        : 1 条
  >>> 上游能发现、JSAtlas 现状漏掉: 1 条
       'a1f3e9d8c7b6a5948271605f4e3d2c1b0a9f8e7d6c5b4a3928'
```

**这是决定性证据：minified JS 上，JSAtlas 会整份漏检密钥。**

真实 bundle `app.8bc848d6.js`（2,717,783 字符 / 62,956 行）上的暴露面：

```
超过 3500 阈值的行: 22 行, 合计 289,621 字符（占全文 10.7%）
把这 22 行单独对照: 现状 0 条 vs 展开后 0 条
```

该 bundle 的这 22 行里恰好没有密钥，所以本次实测差异为 0。
但 **10.7% 的源码从未进入文检这是一个客观事实**，只是样本依赖。

---

## 2. param 提取模块

### 2.1 上游真实流程 —— `params_scan.py` `AISecurityAuditor`

```
scan_multiple_apis(js_code, api_paths, target_url)          # L1318
  Step1  API Path 黑名单  →  is_api_path_blacklisted
  Step2  AST 上下文提取   →  context_extractor
  Level2 _analyze_multiple_api_values(candidates)           # L764  → {api_path: {decision, param_keys}}
  Level3 analyze(context_data, param_keys)                  # L1015 → {path, method, params, dangerous, danger_reason}
  Level3 classify_operation_type(path, method, params)      # L1244 → READ/WRITE/UNKNOWN
```

**Level 2 的三层过滤漏斗（决定是否值得花钱送 AI）** —— `_analyze_multiple_api_values` L764-1009：

```
FRONTEND_ROUTE 上下文 → decision=0 跳过
        ↓
Layer1 AST     context_data["param_score"]
        ↓
Layer2 Bloom   md5(wrapper_code) ∈ _no_param_bloom → decision=0 跳过
        ↓
_filter_caller_codes
        ↓
Layer3 正则    pre_filter_has_params(wrapper, callers, api_path)
        ↓
闸门  ast_score <= 0 and not regex_hit → decision=0 跳过
        ↓
代码压缩 wrapper→CODE_MAX_LENGTH//2，callers 前 3 个→//6
        ↓
★ LLM  SYSTEM_PROMPT_JUDGE + "请对该单一 API 的全量源码进行审查，提取 HTTP 参数名"
        ↓
_parse_level2_result → {has_value, param_keys}
        ↓
has_value==0 → bloom.add(wrapper_hash) 下次省掉
```

关键： **`param_keys` 的唯一来源就是这一步 LLM**。上游不存在任何确定性的参数名提取器。

**`_parse_level2_result` 的容错口径（L179-276）**，每条都要照抄：

- 空返回 → `{has_value:1, param_keys:[]}`（**默认是"有参数"**）
- list → `{has_value:1, param_keys:[]}`
- JSON 解析异常 → `{has_value:1, param_keys:[]}`
- 单字母过滤：`len(k) > 1 or k.lower() in ["id","ip","os"]`

**Level 3 `analyze()`（L1015-1226）**：

- FRONTEND_ROUTE → `return None`
- `value_hint` 由 `request_validation` 开关二选一：
  - `True`：禁止用代码真实值，必须造同类型假值（`orderId→999999999, userId→-1, phone→10000000000`）
  - `False`：提取代码真实值，无法确定时按语义给合理默认值
- `SYSTEM_PROMPT_ADVISORY` + user prompt，`max_tokens=2000, temperature=0.2`
- `_clean_json_response` → `json_repair.loads`
- **回填 `parsed["path"] = api_url`**，补 `dangerous=False` / `danger_reason=""`
- 输出 `{path, method, params, dangerous, danger_reason}`，其中 **`params` 是字符串** `"k1=v1,k2=v2"`

**字符串 → dict 的转换**（`request_executor.py:47-91` `_parse_params_string`），这一步解释了模板里 `"userId": ""` 的来源：

```python
if params_str.startswith('{'): 解析为 JSON dict
separator = ',' if ',' in params_str else '&'
"k=v" → params[k] = v
无 "=" 的项 → params[item] = ""      # ← 空字符串的出处
```

### 2.2 逐项差异

| # | 环节 | 上游 | JSAtlas | 判定 |
| --- | --- | --- | --- | --- |
| P-01 | **参数名来源** | **Level 2 LLM**（`SYSTEM_PROMPT_JUDGE`） | AST 对象键 / query / 路径模板 | ❌ **方法根本不同** |
| P-02 | 参数值来源 | **Level 3 LLM** + `request_validation` 开关 | AST 字面量；非常量留空 `""` | ❌ 不同 |
| P-03 | method 来源 | **Level 3 LLM** | `path_candidates` 语法推断 | ❌ 不同 |
| P-04 | 单字母过滤 `len>1 or in{id,ip,os}` | 有 | 无 | ❌ 不一致 |
| P-05 | `pre_filter_has_params` 实现 | `param_pre_filter.py`（79 行） | **逐字迁移，diff 0** | ✅ 一致 |
| P-06 | `pre_filter` 是否启用 | 每个候选必调用（省钱闸门） | **默认未启用** | ⚠️ 搬了没接 |
| P-07 | 三层漏斗（AST score / Bloom / 正则） | 有 | 无 | ⚠️ 无 AI 时闸门无意义 |
| P-08 | FRONTEND_ROUTE 上下文过滤 | 有（`_classify_context_type`） | 无 | ❌ 缺失 → 前端路由可能被当 API |
| P-09 | API Path 黑名单 | `is_api_path_blacklisted` | 无 | ❌ 缺失 |
| P-10 | `has_value==0` 写 Bloom | 有 | 无 | ⚠️ 无 AI 时不适用 |
| P-11 | 代码压缩 `_compress_code_loop` / `_structural_truncate` | 有 | 无 | ⚠️ 无 AI 时不需要 |
| P-12 | params 字符串→dict（`_parse_params_string`） | `,`优先/无`=`则空值 | 直接产出 dict，非常量同样留空 | ⚠️ **结果形态接近**，语义等价度高 |
| P-13 | `classify_operation_type` READ/WRITE | LLM（`SYSTEM_PROMPT_OPERATION_CLASSIFY`） | 无 | ❌ 缺失 |
| P-14 | `dangerous` / `danger_reason` | Level 3 LLM | 无 | ❌ 缺失 |
| P-15 | Level 2/3 的容错默认值（一律 `has_value=1`） | 有 | 无（无 LLM 即无此环节） | ❌ 缺失 |

### 2.3 关于"API 修正"

**`params_scan.py` 里不存在任何名为"修正/纠正"的逻辑**（全仓库 grep `修正|纠正|correct` 命中 0 处）。

上游真正会**改动 API 地址**的是另外两个 Agent，都在 `processor/analysis/api/`：

| Agent | 文件 | 作用 | 调用点 | 手段 |
| --- | --- | --- | --- | --- |
| BaseURL Agent | `base_url_agent.py`（352 行） | 确定生产环境真实 baseURL，修正 endpoint 拼接基准 | `crawler/response_process.py:77` `verify_base_url` | LLM + 发 HTTP 验证 |
| Prefix Agent | `prefix_agent.py`（292 行） | 判断该用 `domain+path` 还是 `domain+prefix+path` | `main.py:649` | 先机械预判（响应差异），不定则 LLM |

两者都依赖**真实发 HTTP 请求**做 A/B 验证。JSAtlas 侧完全没有对应实现，
`analyzers/surfaces/base_url.py` 只是同名的 AST 写入点定位，不是同一个东西。

按 PROJECT_SPEC 2.2「不默认向提取到的 API 发起请求」，这两个**本来就在首期不迁移范围内**，
所以不是遗漏，但要明白代价：**输出里的 path 是源码原样，没有做拼基重组与前缀校正**。

---

## 3. 提示词

### 3.1 上游全部 8 条 prompt 的位置

| # | 常量名 | 位置 | 用途 |
| --- | --- | --- | --- |
| 1 | `_SYSTEM_PROMPT_JUDGE` | `prompts/prompts.py:4-24` | Level 2 参数名提取 |
| 2 | `_SYSTEM_PROMPT_ADVISORY` | `prompts/prompts.py:29-41` | Level 3 参数值 + 请求构建 |
| 3 | `_SYSTEM_PROMPT_RESPONSE_ANALYSIS` | `prompts/prompts.py:46-74` | 响应判定未授权访问 |
| 4 | `_SYSTEM_PROMPT_BASEURL_RESOLVE` | `prompts/prompts.py:79-99` | BaseURL 候选求值 |
| 5 | `_SYSTEM_PROMPT_BASEURL_JUDGE_ROUND` | `prompts/prompts.py:104-127` | BaseURL 每轮vote |
| 6 | `_SYSTEM_PROMPT_PREFIX_VERIFY` | `prompts/prompts.py:132-151` | 前缀校正 A/B 判定 |
| 7 | `_SYSTEM_PROMPT_OPERATION_CLASSIFY` | `prompts/prompts.py:156-179` | READ/WRITE 分类 |
| 8 | `SECRET_PROMPT` | `secret/prompt.py:4-37` | 密钥 AI 复核 |

### 3.2 JSAtlas 现状

```
grep -rn "openai|llm|LLM|client\.chat|ai_client" src/jsatlas/
→ 0 命中
```

**JSAtlas 全项目零 prompt、零 LLM 调用。** 上表 8 条一条都没迁移。

### 3.3 三条与本次核对直接相关的 prompt 原文摘录

> 之所以原文摘录而不是转述：核对 prompt 时，标点、编号、空行都可能是语义的一部分。

**Level 2（参数名）——`_SYSTEM_PROMPT_JUDGE`**

```
角色：SRC 漏洞挖掘架构师。

任务：从 JS HTTP 请求代码中提取“业务可控参数名”。

【规则】
1. 仅从 HTTP 请求的 params、query、data、body 等实际请求参数中提取。
2. 优先提取代码中直接出现的显式属性名，禁止根据语义猜测或捏造。
3. 忽略单字母/无意义变量名，如 e、t、n、r、o、a。
4. 忽略明显的签名、时间戳、随机数及协议封装字段，如 sign、signType、timestamp、nonceStr、version 等。
6. 参数无法可靠确定时宁少勿多。

【输出】
纯 JSON：
{"has_value":1,"param_keys":["orderId","content"]}
```

> 注：上游原文规则编号从 4 直接跳到 6，**缺第 5 条**。这是上游既有瑕疵，若要复刻需原样保留。

**Level 3（值 + 请求构建）——`_SYSTEM_PROMPT_ADVISORY`**

```
角色：资深 SRC 漏洞挖掘专家。
任务：基于 JS 代码和 Level 2 参数名线索，提取完整请求信息。

【规则】
1. Level 2 参数名仅供参考，以代码为准；忽略单字母变量
2. Method：从代码提取(GET/POST)，无法提取时输出""
3. 参数值要求见用户提示中的说明
4. 忽略签名/协议信封字段：version、nonceStr、timestamp、signType、sign、merchantId 等固定基础设施字段不是业务参数，不要输出
6. params 格式为 "key1=value1,key2=value2"，不要输出 JSON 对象

【输出格式】纯 JSON：
{"method": "GET/POST或空", "params": "k1=v1,k2=v2"}
```

> 同样缺第 5 条。

**Level 3 user prompt 模板（L1145-1154）**

```
{param_keys_hint}=== 【前端 JS 代码证据】 ===
{full_code}

目标 API: {api_url}

{value_hint}

请严格按照 Prompt 要求提取请求信息。
```

其中 `full_code`：

```
[底层发包函数 (Wrapper)]
{wrapper_code}

[高层业务调用点 (Callers)]
--- 业务调用点 1 ---
{caller_1}
```

**密钥复核——`SECRET_PROMPT`**

```
角色：资深安全研究员 & 渗透测试专家
目标：分析 JavaScript 代码中的硬编码敏感字符串，并提供可执行的测试指导

输入格式：
- value: 硬编码的字符串值
- context: 显示该值如何定义/使用的代码片段
- callers: 调用该值的代码位置列表

分析标准：
1. 这是否是真正的秘密？(许可证密钥、API Token、密码等)
2. 它是什么类型的秘密？
3. 风险等级是什么？(High/Med/Low)
4. 渗透测试人员如何利用它？

输出格式：
为每个候选 ID 返回一个 JSON 对象，结构如下：
{
  "id": {
    "is_secret": 1 或 0,
    "secret_type": "license_key|api_key|token|password|endpoint|other",
    "risk_level": "High|Med|Low",
    "confidence": 0.0-1.0,
    "test_suggestion": "具体的、可执行的渗透测试步骤（中文）"
  }
}

风险等级指南：
- High: 可直接用于未授权访问、认证绕过或数据泄露
- Med: 可能导致信息泄露，或需要额外条件才能利用
- Low: 可能是误报、构建产物或低影响配置

策略：如果不确定，标记为 is_secret=1 (召回率 > 精确率)，但降低 confidence 分数。
```

### 3.4 一个重要发现

你给的输出模板：

```json
{ "apis": [{"path", "method", "params", "source"}],
  "secrets": [{"value", "type", "risk_level", "test_suggestion", "source"}] }
```

**正好等于上游两条 AI 产线的并集**：

- `apis` ← Level 3 `analyze()` 的 `{path, method, params}` + 来源
- `secrets` ← `SensitiveInfoScanner.scan()` 的 `{value, secret_type, risk_level, test_suggestion}` + 来源

也就是说，这个模板描述的是**上游开了 AI 之后的输出形态**。JSAtlas 现在用确定性方法填同一张表，
字段对得上，但**填充方式不是同一套**。这不是缺陷，是一个必须明示的事实。

---

## 4. 需要你拍板

差别太多了，补哪一段决定要不要突破「不强制依赖 LLM」这条架构红线。按性价比排序：

| 优先级 | 建议 | 收益 | 代价 |
| --- | --- | --- | --- |
| **P0** | 补 S-01/S-02 预处理（`remove_html_tags` + `format_code`） | minified JS 从"整份漏检"变成能扫；纯确定性改动，不碰红线 | 引入 `jsbeautifier` 依赖，大文件有耗时 |
| **P1** | 补 P-08 API 黑名单 + P-09 FRONTEND_ROUTE 过滤 | 明显降噪，两者都是纯确定性 | 需迁移 `scanner_rules` 的黑名单表与上下文分类逻辑 |
| **P2** | 把 8 条 prompt 原样搬进 `analyzers/*/prompts.py` 并设为**可选阶段** | prompt 得以沉淀和对拍；默认关闭，红线不破 | 需加 AI client 适配层（类似上游 `infra/ai_client.py`） |
| **P3** | 完整复刻 Level 2 / Level 3 / `LLMSecretVerifier` | 真正达到"完全一致" | 强制依赖 LLM，与 PROJECT_SPEC 2.2/3 冲突，需要你先改约束 |

**我的建议是先做 P0 + P1**：这两步都是纯确定性的，能显著缩小与上游的行为差（尤其 S-02 是
实打实的漏检），又不引入任何"必须有大模型才能跑"的依赖。P2/P3 等你要接 AI 时再做。

---

## 9. 第二轮核对结论（第二批迁移后）

**核对日期：** 2026-10-09（同日）
**触发：** 用户明确目标 —— 入口改成 URL/代码/文件，出口改成 JSON，**中间逻辑全部不变**

### 9.1 判定总表（更新）

| 核对项 | 第一轮 | 第二轮 | 依据 |
| --- | --- | --- | --- |
| secret 识别方式（正则链路 `-asir`） | ✅ 一致 | ✅ 一致 | 逐值对拍不变。**注：该链路已于 2026-10-10 按项目决策移除（B-19）** —— 与上游一致不等于在 JSAtlas 的输出口径下可用：真实 bundle 上 43 条命中全是语言包文案误报 |
| secret **预处理**（HTML 剥离 + 格式化） | ❌ 缺失 | ✅ **一致** | `parsing/preprocess.py`、`utils/html.py` 逐字迁移 |
| secret 统计打分算法 | ✅ 一致 | ✅ 一致 | 公式/权重/阈值未动 |
| secret 编排（含上下文富化、优先级裁剪） | ❌ 缺失 | ✅ **一致** | `upstream_secret_scanner.py` 逐字迁移编排段 |
| secret **AI 复核过程** | ❌ 完全缺失 | ✅ **已迁移**（可选） | `LLMSecretVerifier` + `secret_prompt.py` 逐字迁移；未配 Key 时降级并标 `ai_verified=False` |
| param **提取方式** | ❌ 方法根本不同 | ✅ **一致 + 兜底** | `upstream_params.py`（`AISecurityAuditor` 全链路）逐字迁移；无模型时另由确定性分析器兜底 |
| param **提取逻辑**（黑名单/三层漏斗/路由过滤） | ❌ 缺失 | ✅ **一致** | 同上，Blacklist Step 1 与上下文类型过滤均按上游执行 |
| param **AI 参数识别过程** | ❌ 完全缺失 | ✅ **已迁移**（可选） | Level 2 / Level 3 全在，8 条提示词全在 |
| **提示词** | ❌ 8 条全未迁移 | ✅ **8 条全部逐字一致** | `test_prompts_identical_to_upstream` 逐条比对通过 |
| API 修正（BaseURL/Prefix Agent） | ❌ 缺失 | ❌ 仍缺失（**有意**） | 需真实发 HTTP 验证，属 PROJECT_SPEC 2.2 明确不迁移范围 |

### 9.2 关键差异：AI 阶段从"必需"变成"可选"

上游 `-asia` 未开时整条链路不跑；开了则**必须**有模型 —— `params_scan.py` 的 Level 2
会因取不到 client 而抛异常。JSAtlas 保留了同样的开关语义，但把"没有模型"处理成
**受控降级**而不是崩溃：

* 参数链路：在 Level 2 边界返回与上游"AI 确认无参数"**同结构**的结果，标记 `ai_analyzed=False`；
* 密钥链路：跳过 `LLMSecretVerifier`，结果标记 `ai_verified=False`。

这样做的收益是：确定性分析与 AI 结论在输出里**永远可区分**，
不会把没经过模型确认的候选伪装成已确认结论 —— 这一点上游自身做不到（它的降级路径会把
失败批次直接标成 `is_secret=True`）。

同时这也是**唯一**没能做到"逐字一致"的地方：上游没有这条降级分支。
已在 `docs/migration-map.md` 3.8 节记录，并用注释标注在源码里。

### 9.3 仍然存在的 gap

1. **无模型时的 `type` / `risk_level` / `test_suggestion` 不是上游口径。**
   这三个字段在上游由 LLM 产出。没配模型时 JSAtlas 给的是
   `high_entropy_value / Low / "未经 AI 复核…"`，明确声明这是确定性结果的兜底标签，
   不是模型判断。AI 已默认开启，配好 `JSATLAS_LLM_API_KEY` 后这三个字段就是上游口径。
2. **API 修正确实不存在**，且不是遗漏 —— 详见第 3 节。输出的 `path` 是源码原样。
3. **跨运行去重语义变了**：上游 Bloom 落盘跨班次复用，JSAtlas 改成单次调用内的
   朴素 `set` 去重 —— 只保留单次运行内去重，不做综合去重，也不再使用布隆过滤器。
   这是无状态 API 的必然取舍，见 `migration-map.md` 3.8。
4. **上游的体积保护已被移除**（JSAtlas 主动分叉，不是迁移偏差）：
   `find_all_info_by_rex` 的 100 万字符保护、密钥/参数链路的 200 万字符保护、
   以及 JSAtlas 自己加过的输入层 32MB、远程 8MB、`max_context_targets=200`、
   `_MAX_SURFACES=5000`。上游在大文件上会**整条链路跳过**，JSAtlas 选择跑完。
   判定逻辑本身没动，动的是"要不要跑"。见 `migration-map.md` B-14。

### 9.4 验证方式

```bash
python -m pytest tests/unit/test_upstream_parity.py -v
```

该测试把 9 个迁移文件**剥掉 import 后与上游逐字节比对**，并用 AST 断言
没有残留 `processor.* / infra.* / config.* / storage.* / logger` 引用。
任何超出"改 import"范围的改动都会让测试失败。
