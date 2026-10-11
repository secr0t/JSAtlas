# JScanner2 → JSAtlas 迁移映射

> Phase 0 交付物。本文件记录**第一批迁移**的审计结论、每个模块的来源、改动点、
> 行为变化与已知限制。后续每迁移一个模块，必须在这里追加一条记录。
>
> 上游根目录：`C:\Users\Cheng\Desktop\JScanner2`（git HEAD 于审计时的工作区状态）

## 1. 审计方法

对每个候选模块回答六个问题，答不上来就不迁：

1. 真实调用入口是谁（不是"看起来像入口"的函数）；
2. 输入形态与输出形态；
3. 副作用（写文件 / 写库 / 发请求 / 改全局状态）；
4. 对上游 config、logger、storage、调度器的依赖强度；
5. 能否脱离上游独立跑起来；
6. 应直接复用、重构，还是重新实现。

**判定原则：迁移的是"经过验证的能力"，不是目录结构。**
凡是需要拖着上游运行环境才能跑的，一律不进核心层。

---

## 2. 结论总览

| 上游路径 | 能力 | 决策 | 落到 JSAtlas |
| --- | --- | --- | --- |
| `processor/js/context/param_scoring.py` | 参数信号评分 | ✅ 逐字迁移 | `analyzers/parameters/param_scoring.py` |
| `processor/js/context/context_extractor.py` | 上下文恢复 | ✅ 逐字迁移 + 1 处缓存（B-17） | `analyzers/context/context_extractor.py` |
| `processor/js/context/base_url_extractor.py` | baseURL 写入点 | ✅ 逐字迁移 | `analyzers/surfaces/base_url_extractor.py` |
| `processor/js/context/js_line_extractor.py` | 行级预筛 | ✅ 迁移（常量内联） | `analyzers/surfaces/line_prefilter.py` |
| `processor/analysis/secret/js_sensitive_rex.py` | 敏感信息正则 | ⛔ **迁移后移除**（B-19） | 曾落到 `secret_regex.py` / `upstream_regex.py`，真实 bundle 上 43 条全误报，已删除 |
| `processor/analysis/secret/secret_scanner.py` | 密钥 Orchestration 全链路 | ✅ 迁移 | `analyzers/intelligence/upstream_secret_scanner.py`（编排 + LLM 复核）<br>`analyzers/intelligence/secret_scoring.py`（确定性打分核心） |
| `processor/analysis/params/param_pre_filter.py` | 参数预筛 | ✅ 迁移（备用） | `analyzers/parameters/param_pre_filter.py` |
| `config/scanner_rules.py` 的常量段 | 规则常量 | ✅ 复制数据 | `analyzers/intelligence/constants.py` |
| `processor/analysis/params/params_scan.py` | 参数分析主流程 | ✅ 迁移 | `analyzers/parameters/upstream_params.py`（`AISecurityAuditor` 全链路）<br>`analyzers/parameters/explicit_params.py`（无模型时的确定性兜底） |
| `processor/analysis/prompts/prompts.py` | 7 条通用提示词 | ✅ 逐字迁移 | `analyzers/prompts/prompts.py` |
| `processor/analysis/secret/prompt.py` | 密钥复核提示词 | ✅ 逐字迁移 | `analyzers/intelligence/secret_prompt.py` |
| `infra/ai_client.py` | 多模型 AI 客户端 | ✅ 迁移（改依赖注入） | `llm/client.py` + `llm/openai_compat.py` |
| `processor/js/format/js_formatter.py` | JS 格式化预处理 | ✅ 逐字迁移 | `parsing/preprocess.py` |
| `processor/js/format/options.py` | 格式化选项 | ✅ 逐字迁移 | `parsing/beautify_options.py` |
| `config/scanner_rules.py`（全文） | 黑名单与关键词规则集 | ✅ 逐字迁移 | `parsing/scanner_rules.py` |
| `infra/utils.py:remove_html_tags` | HTML 包裹剥离 | ✅ 逐字迁移 | `utils/html.py` |
| `request_executor._parse_params_string` | 参数串 → 字典 | ✅ 逐字迁移 | `utils/params_string.py` |
| `processor/analysis/api/api_scan.py` | URL 抽取 | ❌ 不迁移（绑客户白名单 + tldextract） | `analyzers/surfaces/path_candidates.py`（重写） |
| `processor/analysis/api/base_url_agent.py` | baseURL 验证 | ❌ 不迁移（靠真实发 POST） | — |
| `processor/analysis/api/prefix_agent.py` | 前缀聚类验证 | ❌ 不迁移（靠真实发包） | — |
| `processor/analysis/api/request_executor.py` | 请求执行 | ❌ 不迁移（发包验证） | — |
| `processor/js/context/secret_extractor.py` | 敏感串溯源 | ✅ 逐字迁移 | `analyzers/intelligence/secret_context.py` |
| `infra/dedup.py` | 去重 | ❌ 不迁移（与 SQLite/状态机强耦合） | 去重改由稳定 ID + 上下文去重承担 |
| `infra/bloom.py` | 布隆过滤器 | ❌ 不迁移（单次量级用不上，且假阳性会把漏报变成概率问题） | `utils/dedup.py`（朴素 set，单次运行内去重） |
| `crawler/httpx_crawler.py` | HTTP 抓取 | ⏸ Phase 3 适配层 | — |
| `crawler/browser_crawler.py` | 浏览器抓取 | ⏸ Phase 3 适配层 | — |
| `crawler/response_process.py` | 抓取后处理 | ❌ 不迁移（调度层） | — |

---

## 3. 逐模块迁移记录

### 3.1 `param_scoring.py` — 参数信号评分

| 项 | 内容 |
| --- | --- |
| 源 | `test/context_recall/param_scoring.py`（生产版 `processor/js/context/param_scoring.py` 的已验证副本，两者算法一致） |
| 迁移前 md5 | `dc5ff2ac91e6497732c61e7bab183df4` |
| 改动 | **零**。文件逐字复制，未改一行代码 |
| 为什么能零改动 | 该模块只 import `typing` 与 `tree_sitter`，是上游六个 context 模块里唯一没有任何内部依赖的 |
| 接口 | `get_param_score(func_node, api_node, code_bytes, trace=None) -> int` |
| 语义 | `-1`=找不到外层函数（应放行）；`0`=无参数信号；`≥1`=有信号，值越大越强 |
| 必留补丁 | `_same_node`（第 164/227 行）。tree-sitter Python binding 每次访问 `.children/.parent` 都新建 Node，`node is api_node` 恒为 False，曾导致信号 1/3 永不命中。迁移不得丢 |

### 3.2 `context_extractor.py` — 上下文恢复（第一批里价值最高的一块）

| 项 | 内容 |
| --- | --- |
| 源 | `test/context_recall/context_extractor.py`（与生产版算法一致，已做过 305/305 全样本对拍） |
| 迁移前 md5 | `50d46508e2996778c07de957d8c7599f` |
| 改动 | 仅 3 处，均在接口层，**算法主体零改动** |

改动明细：

1. **依赖换源**：`from .parse import get_parser, get_logger` →
   `jsatlas.parsing.parser.get_parser` + `jsatlas.utils.logging.get_logger`。
   上游 `parse.py` 对 logger 包的 import 会牵出 `config.config` → `infra.feishu`，
   意味着 import 一次就可能触发飞书网络告警，并在 CWD 建 `logs/` 目录。
   JSAtlas 的解析层无此外部依赖。
2. **解析器可注入**：`_extract_multiple_apis_from_bytes()` 与
   `extract_multiple_apis_from_raw_code()` 新增可选参数 `parser=None`。
   不传时行为与上游完全一致。
3. `from tree_sitter import Node` 补 `Parser`（类型注解需要）。

| 项 | 内容 |
| --- | --- |
| 接口 | `extract_multiple_apis_from_raw_code(js_code, target_apis, trace=None, parser=None) -> Dict[api, {found, api_url, wrapper_code, caller_codes, param_score}]` |
| 消费方 | `analyzers/context/api_context.py`（把结果转成 surface 属性 + evidence + relationship） |
| 验证 | `tests/regression/parity_with_upstream.py`，与上游生产实现逐字段对拍 |

### 3.3 `base_url_extractor.py` — baseURL 写入点

| 项 | 内容 |
| --- | --- |
| 源 | `processor/js/context/base_url_extractor.py` |
| 迁移前 md5 | `3e63d757442714018cd5da9423096965` |
| 改动 | 仅 import 三行（parse / context_extractor 私有函数 / logger）改指向 JSAtlas |
| 接口 | `find_base_url_definitions(code_bytes, tree, js_url="") -> [{type, code}]` |
| 行为变化 | 上游每个文件会打一条 INFO 日志；JSAtlas 核心层不打日志 |
| 产出 | 同时生成 surface(`base_url`) 与 intelligence(`config/base_url`) —— baseURL 既是攻击面拼图，也是环境配置线索 |

### 3.4 `js_line_extractor.py` — 行级预筛

| 项 | 内容 |
| --- | --- |
| 源 | `processor/js/context/js_line_extractor.py` |
| 迁移前 md5 | `d2481e997e5fbce0ac4c65290914751c` |
| 改动 | `from config.scanner_rules import STATIC_RESOURCE_EXTENSIONS` → 内联该常量集。<br>上游这条 import 会把整个 config 包拖进来（含读配置文件的副作用），而这里只需要一个 set |
| 状态 | ⚠️ 上游全项目 grep 无调用方，是**死代码**。JSAtlas 保留它作为可选的降 token 预筛手段，但默认不在流水线里启用 |

### 3.5 `js_sensitive_rex.py` + 统计评分链路 —— 密钥判定的唯一方法来源

**定调（2026-10-09 修订）：JSAtlas 的 secrets 不做二次发明，判定方法严格等于 JScanner2。**
之前自建的 `rules.py` / `regex_analyzer.py` / `stat_analyzer.py` / `env_analyzer.py`
（含补齐的云 AK / JWT / PAT 规则）**已删除**，判定权全部交回上游两条链路。

**链路一：`secret_regex.py`** —— **已移除（2026-10-10 决策）**

曾逐字迁移（md5 `b50477c8470ef74fc7fe289dc3b4b0ae`），驱动 `upstream_regex.py`：
先调上游 `find_all_info_by_rex(text)` 得到"上游认为命中的集合"，再用与上游同源的
正则补位置、类型、风险等级与建议文案。上游覆盖手机号 / 邮箱 / 内网 IP / JDBC /
身份证 / RSA 私钥头 / 硬编码口令 / Webhook / Swagger-Actuator / SourceMap 共 10 类。

**移除理由**：在真实 bundle（`tests/app.8bc848d6.js`，271 万字符）上跑出的 43 条
secrets **全部是误报**，全部来自同一条 `(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,50})['\"]`：

* 命中的是 i18n 语言包的界面文案 —— `password: "Login password"`、
  `pleaseInputOldPwd: "请输入旧密码"`、`gateMachinePwd: "宇泛闸机密钥"`；
* 更糟的是把 `"Old password:"` 里 `password:` 之后的**闭合引号**当成密码值的起始引号，
  一路吃到下一个引号，输出 `',\n                    newPwdLabel:'` 这种源码片段。

判定权虽在上游，但这条正则的产品形态（"字段名叫 password 就是密码"）在本项目的
输出口径下不成立。JSAtlas 从此**只保留计算式链路**。

**链路二：`secret_scoring.py`**（现为 secrets 的唯一来源）：从 `secret_scanner.py` 中剥出三个**纯确定性**类
`CodeLineFilter` / `SecretMathScorer` / `AdvancedSecretFilter`，打分公式、
权重（`w_e=0.85, w_p=1.2`）、阈值（`0.75`）与长度调节系数**逐字未改**。
`analyzers/intelligence/upstream_scoring.py` 把它们接成流水线上的一环：
命中但没有先验类型的串统一标 `high_entropy_value`，风险等级按打分分档
（≥0.95 High / ≥0.85 Medium / 其余 Low）。

剥掉的部分：Bloom 落盘缓存、SQLite 写入、watchdog 心跳、prettier 子进程、
`LLMSecretVerifier`（AI 复核 —— 第二批已搬回来，且默认启用）。

**链路移除后的分工**：统计打分（+ LLM 复核）是 secrets 的唯一来源，
找的是"形态可疑但无先验类型"的串。手机号、邮箱、内网 IP、JDBC、私钥等
**结构化**凭证不再由 JSAtlas 判定 —— 除非它们同时是高熵串并被打分命中。
这是有意为之的取舍：宁可漏掉结构化线索，也不输出整屏的语言包文案。

### 3.6 `param_pre_filter.py`

| 项 | 内容 |
| --- | --- |
| 源 | `processor/analysis/params/param_pre_filter.py` |
| 迁移前 md5 | `f111e052edbdfd414f49f10c149bb5aa` |
| 改动 | 零 |
| 状态 | 已迁移但**默认不在流水线启用**。它是"要不要送 AI"的省钱闸门，而 JSAtlas 首期不接 AI，等 Phase 4 接入 AI 适配层时再启用 |

### 3.7 重新实现而非迁移的一块

| 能力 | 为什么不迁上游 | JSAtlas 的做法 |
| --- | --- | --- |
| API/URL 抽取 | `api_scan.py` 面向 HTML 抓取场景（内含 BeautifulSoup），且 URL 归一化绑死 `config.config.WHITE_SCOPE_PATH`（客户白名单），还依赖 tldextract | `analyzers/surfaces/path_candidates.py`：纯 AST 字符串字面量提取，不预测路径、不推断域名，方法来自 `method:` 键或 `.get/.post` 调用形态 |

参数名提取这一块已于第二批改为**迁移**（见 3.8），原先"重写"的结论作废。

### 3.8 第二批：把 Orchestration 与 AI 阶段整体搬过来

第二批的出发点是用户明确的目标：**入口改成 URL/代码/文件，出口改成 JSON，中间逻辑全部不变**。
因此这一批一律采取「逐字复制 + 只替换 import 接缝」的做法，不重写任何一个算法。

搬运方式是 `cp` 原文件，然后只做下面这些替换：

| 上游写法 | JSAtlas 写法 | 原因 |
| --- | --- | --- |
| `from logger import get_logger` | `from jsatlas.utils.logging import get_logger` | 上游 logger 包在 import 时会拖出 `config.config → infra.feishu` |
| `from config.scanner_rules import ...` | `from jsatlas.parsing.scanner_rules import ...` | 规则文件是纯数据，整体搬过来即可 |
| `from infra.ai_client import client` | `from jsatlas.llm import get_client` | 见下：客户端改惰性 + openai 降级 |
| `from infra.bloom import DiskBloomFilter` | `from jsatlas.utils.dedup import MemoryDedup` | 见下：不落盘、不用 Bloom |
| `from infra import watchdog` | 本地空实现 `_WatchdogStub` | JSAtlas 没有长任务看门狗 |
| `db.save_xxx(...)` | `return ...` | **这正是"出口改成 JSON"的部分** |

三处不得不做的结构性调整（都已单独记录并被测试锁住）：

1. **`infra/ai_client.py` 的模块级单例改成惰性构造。**
   上游在 import 时就 `client = AIHubClient(...)`，没有 API Key 会让整个包 import 失败。
   JSAtlas 把实例化推迟到真正要调模型的时刻。`openai` 仍是**核心依赖**（AI 是默认
   能力），但加载不硬依赖：`llm/openai_compat.py` 在缺包时给出可操作的安装指引，
   CLI 启动时打印告警，而不是让整个包 import 失败。

2. **`DiskBloomFilter` 换成 `MemoryDedup`（朴素 `set`）。**
   上游在 `Result/*.bloom` 落盘，跨进程跨班次复用 —— 那是"扫描任务"的语义。
   JSAtlas 是无状态的一次性分析调用，落盘会污染运行目录，还会让上一轮结果抑制这一轮。

   去重策略因此明确为两条：**只做单次运行内去重；不做跨运行去重**。
   而且不用布隆过滤器 —— 单次分析撑不起 Bloom 的规模价值，Bloom 的假阳性会把
   "漏报"变成一个概率问题（明明没见过的候选被判定为"见过"而丢掉）。
   `set` 精确、无假阳性，几百到几万条字符串的内存开销可以忽略。

   实现是**每次 `scan()` 开始时新建**内存集合：单次调用内的去重语义与上游完全一致，
   跨调用互不干扰（`test_upstream_parity.py::test_secret_scanner_is_repeatable`
   与 `test_dedup_and_ai_default.py` 一起守着）。

3. **没配模型时，AI 阶段降级而非抛错。**
   AI 是默认能力（没有 `--enable-ai` 开关），所以这里说的是"取不到模型"这一种情况：
   上游参数 Level 2 会直接异常。JSAtlas 在
   `scan_multiple_apis` 的 Level 2 边界加了一处守卫：给出与上游"AI 确认无参数"
   **同结构**的结果（`params: ""`），并标记 `ai_analyzed=False`；
   密钥侧同样跳过 `LLMSecretVerifier`，结果带 `ai_verified=False`。
   这样"确定性结论"和"模型结论"永远可以区分。

`tests/unit/test_upstream_parity.py` 会把这些文件**剥掉 import 后与上游逐字节比对**，
并额外用 AST 断言没有残留 `processor.* / infra.* / config.* / storage.* / logger` 的引用。
也就是说，今后任何人改动这些迁移件的算法逻辑，测试会直接失败。

### 3.9 第二批带来的真实收益：补回了压缩 JS 的召回面

`CodeLineFilter.extract_candidates` 会跳过长度超过 3500 的行。上游之所以不漏，
是因为 `SensitiveInfoScanner._preprocess` 先做了 `remove_html_tags` + `format_code`
把压缩成一行的 bundle 展开。第一批迁移只取了打分类，把这层预处理丢了。

受控对照（同一份 samples，变量只有"是否先展开"）：

```
构造 minified 单行样本: 6,479 字符 / 1 行（> 3500 阈值）
  A 改造前（直接喂原始 minified）: 0 条
  B 改造后（先走上游 format_code）: 2 条
```

这正是你在追踪的那次 Evening-review 里提到的"minified JS 整份漏检"的根因，现已消除。

### 3.10 迁移后发现的上游既有行为（不是缺陷）

`AISecurityAuditor` 的 Step 1 会用 `scanner_rules.is_api_path_blacklisted` 过滤候选。
实测 `/api/v1/order/create` 会被该黑名单命中，因此**不会**进入 Level 2/3。

这是上游规则集本身的取舍，已随规则文件逐字迁移。
`parameters.upstream_pipeline` 因此设计成**只做增量补充**：它不会删除别处已提取到的
surface 或 point，黑名单的影响范围被限制在这条 AI 链路内部。

## 4. 首期不迁移的能力及理由

按 PROJECT_SPEC 2.2 / 6.3：

* **发包验证类**（`base_url_agent` / `prefix_agent` / `request_executor`）：核心逻辑建立在真实发 HTTP 请求之上，属扫描执行，与"静态情报提取"正交，且 JSAtlas 明确"默认不向提取到的 API 发起请求"。
* **扫描调度与状态机**（`dedup.py`、`storage/*`、`ApiStatus` 转移表）：`dedup.py` 与 SQLite 的状态机深度耦合（6 正常态 + 4 失败态 + 转移表），那是上游"发现→Context→AI→验证"流水线专属的调度设施，与 JSAtlas 的实体生命周期不同构。**去重改由稳定 ID 天然承担**。
  注意：`params_scan.py` 的**主流程编排已在第二批迁移**（见 3.8），不迁的只是它被剥离出来的 DB 状态推进与重试閾值那部分。
* **报告 / 通知 / UI**：不在本期范畴。
* **Bloom 过滤器**：按 PROJECT_SPEC「仅在规模和性能需求证明必要时迁移」不迁。
  单次分析的量级（几百到几万条）用不上 Bloom，而它的假阳性会让"漏报"变成概率问题；
  去重改用 `utils/dedup.py` 的朴素 `set`，只做单次运行内去重，不落盘、不跨运行复用。

---

## 5. 已知限制（沿用上游，未擅自改算法）

| 编号 | 限制 | 触发条件 | 处理 |
| --- | --- | --- | --- |
| K-01 | 常量传播会把变量值替换回**声明处**，产出 `var "值" = '值';` 这种畸形切片 | 目标 API 字符串本身就是某个变量的字面量值 | **已确认上游同款**（`examples/input.js` 的 `API_HOST = 'https://api.example.com'` 复现）。不擅自修算法（会影响对拍基线），在此记录，后续作为独立优化项 |
| K-02 | API 匹配是子串包含，短路径串会命中多处；同一节点命中多个 API 时只记第一个（`break`） | API 路径很短（如 `/a`） | 影响的是候选质量，不丢攻击面；下游按 location 去重 |
| K-10 | 上游 JDBC 正则 `jdbc:[a-z:]+://[^\"\s]+` 只排了双引号和空白，遇到单引号包裹的字面量会一路把 `';` 吞进结果 | `const db = 'jdbc:mysql://...';` | **判定仍按上游**（命中集合来自 `find_all_info_by_rex`），仅在不影响判定的前提下清理展示值，原始形态可通过 `attributes` 追溯。这是 K-10，不是改动算法 |
| K-03 | `_find_semantic_boundary` 里写了 tree-sitter JS 不存在的节点类型 `'function'`（应为 `function_expression`），该分支永不命中 | — | 记录，未改（改了会与上游行为分叉） |
| K-04 | 多重递归无深度保护；`_build_scope_chain` 对每个 identifier 重建作用域并全子树扫描 | 大 bundle | **已用缓存缓解（B-17）**：同一作用域节点的声明列表只扫一次，实测 120 个 API 下递归 2700 万次 → 2.6 万次、耗时 15.9s → 1.4s，输出逐条一致。另保留 `max_context_targets` 字段作手动闸门，**默认 0 = 不限**（见 B-14） |
| K-05 | caller 召回在 webpack 产物上常为 0 | webpack 的 API wrapper 多为 module 私有名，真实调用方走 export 名跨模块引用 | **这是预期结果**（上游 README 已记录：400 个 API 的 caller 全部归零是作用域过滤生效的证明）。JSAtlas 不把它当缺陷 |
| K-06 | `param_score` 在上游下游并未真正接通（只出现在字段白名单里） | — | JSAtlas 显式写进 `surface.attributes`，并附 `param_score_meaning` 人话解释 |
| K-07 | 仅支持 JavaScript，不含 TS / JSX | — | 解析层已留 `set_parser()` 注入点，后续扩语言不需要改分析器 |
| K-08 | `base_url_extractor` 只定位写入点，不解析实际 URL 值；属性名硬编码 11 个（缺 `basePath` / `VUE_APP_BASE_API` 等） | — | 已在输出 attributes 里标注 `note` |
| K-09 | `js_line_extractor` 强依赖换行，minified 单行 JS 会被整行丢弃 | 压缩产物 | 该模块默认不启用 |
| K-11 | **整包传参（`data: t` / `params: t`）的参数名确定性解不开** | Vue/React 产物：`const t = JSON.parse(JSON.stringify(r)); request({url, method, data: t})` | 参数名藏在组件 `data()` 里，静态 AST 到不了。上游同理——它的 Level 2/3 就是拿 AI 去读上下文。**没配 Key 时这类接口必然没有 params**，实测 2932 个里 2917 个如此。已把「缺 `params` = 未提取到」的语义写进 schema / README / `report.py` 文档串，防止下游误读成"确认无参数"（B-18） |

---

## 6. 行为变化清单（相对上游）

| 编号 | 变化 | 原因 |
| --- | --- | --- |
| B-01 | import JSAtlas 不再建 `logs/` 目录、不再可能发飞书告警 | 日志层剥离 `config` / `infra` 依赖 |
| B-02 | 不再有 Bloom 落盘文件、不再写 SQLite、不再调 watchdog | 缓存与状态是调度层职责，核心分析保持无副作用 |
| B-03 | 不再自动 `nltk.download()` 联网取语料；取不到就退回内置词表并告警 | 核心分析不允许网络副作用 |
| B-04 | 解析器可注入（`set_parser()` / `parser=` 参数） | 便于测试与多语言扩展 |
| B-12 | AI 默认开启，CLI 不再有 `--enable-ai`；取不到模型时降级并打 `ai_verified=False` / `ai_analyzed=False` | 工具默认就需要 AI（对应上游 `-asia`）；降级是兜底路径，不是开关。与 PROJECT_SPEC 4「AI 作为可选增强」的表述差异以此为准 |
| B-13 | 去重只做**单次运行内**，用朴素 `set` 而非布隆过滤器，不落盘、不跨运行复用 | 单次量级撑不起 Bloom 的规模价值，假阳性会把漏报变成概率问题；跨运行去重是调度层职责 |
| B-14 | **移除全部源码体积上限**：`_MAX_TEXT_CHARS`（正则 100 万 / 密钥与参数各 200 万）、输入层 32MB、远程 8MB，以及 `max_context_targets` 默认 200 | 跳过或截断的代价是整段源码线索全部丢失，那是漏报不是优化。需要自保时用 `--max-bytes` / `--max-context-targets` 显式设，默认一律不限 |
| B-15 | 模型调不通时**不再静默丢弃候选**：上游 `_verify_with_single_api` 在 `_call_llm` 返回空时直接 `return []`，整批候选消失且不留痕迹；JSAtlas 改成退回确定性结果并打 `ai_verified=False` | 上游没有"是否经过模型确认"这个概念。失败批次若沿用上游的 `is_secret=True / risk Med`，下游会读成"AI 已复核为 Medium 风险" —— 把失败伪装成结论 |
| B-16 | `LLMSecretVerifier` 拿的是**解析后**的 client（`self.client`）而不是构造入参 | 上游 client 是必传的模块级单例，写 `LLMSecretVerifier(client)` 永远有值；JSAtlas 改成惰性解析后，照抄会让 verifier 恒为 None，报 `'NoneType' object has no attribute 'chat'` |
| B-05 | 敏感信息输出带 `sub_type / risk_level / test_suggestion` | 上游是无类型的字符串集合，下游无法直接消费 |
| B-06 | 语法错误时 `statistics.parsed = False` 并给出告警 | tree-sitter 是容错解析器，出错仍返回树；必须显式告知"这是部分解析结果" |
| B-07 | 每个实体带稳定 ID，同输入同分析器必得同 ID | 上游用 `list(set(...))`，顺序受 hash 随机化影响，不可复现 |
| B-08 | **对外输出只有 `apis` + `secrets`**，五类内部实体不再出现在 JSON 里 | 下游要的是可直接消费的清单；完整内部模型保留在内存里供调试与回归 |
| B-09 | 删除自建的 `rules.py` / `regex_analyzer.py` / `stat_analyzer.py` / `env_analyzer.py` | 判定方法必须与 JScanner2 严格一致，不并行维护第二套规则 |
| B-10 | 字符串拼接的后续片段不再作为独立 API 输出（如 `'/a/b/' + id + '/delete'` 里的 `/delete`） | 单独一条 `/delete` 没办法直接请求，放进清单只会误导下游 |
| B-11 | 纯域名与 baseURL 本身不进 apis | 它们不是可请求接口，只是前缀配置 |
| B-18 | **api 项里 `params` 为空时整个键不写**，而不是给 `"params": {}` | 2932 个接口里 2917 个没有参数（K-11，AI 阶段没跑），`{}` 是纯噪声。更重要的是语义：`"params": {}` 会被读成"该接口无参数"，而真相是"没提取到"。缺键 + 文档明示"= 未提取到"，比一个空对象更诚实。schema 已把 `params` 从 `required` 移除 |
| B-20 | **补回 `AdvancedSecretFilter.shannon_entropy` + 密钥链路规模统计** | 迁移上游 `secret_scanner.py` 时只搬了 `is_secret`，漏了这个方法，而 `_priority_sort` 会调它：候选 > 50 时 AST 富化处的 `except` 把 AttributeError 吞掉（上下文静默全空），候选 > 80 时 `scan()` 里没有 try 保护，异常直接抛到分析器 —— **整条链路 fail、secrets 恒为 0 条**。真实 bundle 只有 8 条候选所以没触发，属于定时炸弹。同时把 `candidates / kept / ai_used` 写进 `statistics.analyzers`，让"secrets 为空"能区分"没候选"和"被 LLM 否掉了" |
| B-19 | **移除正则密钥链路**（`secret_regex.py` / `upstream_regex.py`，对应上游 `-asir`），secrets 只留计算式来源 | 真实 bundle 上该链路 43 条命中全是误报：i18n 语言包的 `password: "Login password"` 类文案被当成硬编码口令，还把 `"Old password:"` 的闭合引号当成值起点（`,\n newPwdLabel:`）。代价是手机号/邮箱/内网 IP/JDBC/私钥等结构化凭证不再判定 —— 宁可漏，也不输出整屏文案 |
| B-17 | **`_collect_decls_in_subtree` 加声明列表缓存**（per-thread + per-call，按 `node.id` 记忆化） | 这是本文件第一处算法层偏离。该函数是纯函数（只依赖 node），却被每个变量查找重复调用：实测 120 个 API 下递归 **2700 万次 → 2.6 万次**、耗时 **15.9s → 1.4s（11×）**，输出逐条一致。详见 `docs/perf-scope-cache.md`。之所以敢改：它是纯函数（唯一输入是 `node`，唯一副作用是 append），
DFS 顺序不变。原函数以 `_uncached` 逐字保留，`tests/unit/test_scope_cache.py` 守住 cached/uncached 等价与缓存隔离 |

---

## 7. 回归与对拍

| 验证 | 位置 | 当前结果 |
| --- | --- | --- |
| 与上游生产实现逐字段对拍 | `tests/regression/parity_with_upstream.py` | `scope_sample.js` 5/5 一致；`app.8bc848d6.js`（2.96MB 真实 webpack 产物）120/120 一致 |
| 已知真值 caller 回归 | `tests/regression/test_scope_sample.py` | `/org/list`=2、`/other/list`=1、`/rest/list`=3 |
| 迁移件无上游残留依赖 | `test_migrated_module_has_no_upstream_imports` | 通过 |
| 输出结构 / Schema 校验（`report-v1.schema.json`） | `tests/unit/test_schema.py` | 通过 |
| 对外契约只有两个顶层块 | `test_report_only_has_two_top_level_keys` | 通过 |
| 端到端 | `tests/integration/test_pipeline.py` | 通过 |

对拍脚本说明：

```bash
# 默认样本
python tests/regression/parity_with_upstream.py

# 加跑大样本（真实 webpack 产物，耗时较长）
JSATLAS_BIG_SAMPLE=<path-to-app.js> python tests/regression/parity_with_upstream.py
```

它加载的是**上游生产实现**（`processor/js/context/context_extractor.py`），
不是 `test/context_recall/` 那份副本 —— 避免自己和自己比。
上游 `parse` 模块用 shim 替换成裸 tree-sitter parser：替换的是依赖，不是算法。

候选 API 由 JSAtlas 自己的 `surface.path_candidates` 产出后同时喂给两侧，
保证输入完全一致。

---

## 8. 下一批建议

1. `secret_extractor.py`（敏感串 AST 溯源）—— 需要先把它依赖的 4 个 context 私有函数提升为正式 API，否则跨模块私有 import 会随上游重构断裂。
2. `params_scan.py` 的**代码压缩**部分（282-539 行）—— 纯确定性，且是控制 AI token 成本的关键。
3. 修 K-01：改 `_propagate_variables`，让替换跳过声明标识符。建议先在独立副本里改 → 对拍 → 再合入。
4. Phase 3 的输入适配层：`httpx_crawler` / `browser_crawler` 按"可选适配器"形态接入。
