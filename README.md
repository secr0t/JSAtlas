# JSAtlas

**JavaScript Security Intelligence Engine** —— 从 JavaScript 源码里把
**可请求的接口清单**和**可疑密钥清单**挖出来，用一份干净的 JSON 交给你。

上游项目：JScanner2。JSAtlas 不是对它的改名或复制，而是把其中经过验证的
分析能力重组为独立、可复用、可单测的基础能力。密钥判定方法严格沿用 JScanner2。

> JSAtlas 输出的是**安全情报和分析依据**，不是未经验证的漏洞结论。

---

## 安装

```bash
pip install -e .
```

核心依赖 `tree-sitter`、`tree-sitter-javascript`、`jsbeautifier`、`json_repair`
在上游同样是硬依赖，缺失会导致搬过来的模块无法加载，因此放在 `dependencies` 里。

可选依赖（缺了也能跑，只是能力降级）：

```bash
pip install nltk wordninja      # 统计评分的词典与分词，缺失时退回内置词表
pip install jsonschema          # 严格的 JSON Schema 校验，缺失时退回内置结构校验
pip install requests            # 远程 URL 输入，缺失时自动退回标准库 urllib
```

`openai` 在**核心依赖**里 —— AI 是默认能力，不是可选开关。环境缺包时也不会
import 即崩：`llm/openai_compat.py` 会兜底，CLI 启动时打印告警，AI 阶段降级为
确定性结果（见下）。

需要 Python ≥ 3.9。

---

## 快速开始

### 命令行

```bash
# 分析一个文件，输出 JSON 到 stdout
python -m jsatlas path/to/app.js

# 写到文件
python -m jsatlas path/to/app.js -o result.json

# 只跑某一个分析器
python -m jsatlas app.js --analyzers surface.path_candidates

# 输出前校验
python -m jsatlas app.js --validate

# 看看有哪些分析器
python -m jsatlas --list-analyzers
```

### 远程 URL

```bash
# 直接给 JS 的 URL
python -m jsatlas https://example.com/static/app.js -o result.json

# 多个目标（可混用 URL 与本地文件），并发获取，合并成一份清单
python -m jsatlas https://a.com/a.js https://b.com/b.js local.js --workers 8

# 带 Cookie 抓需鉴权的 JS
python -m jsatlas https://x.com/app.js --header "Cookie: session=xxx"

# 自签名证书环境
python -m jsatlas https://internal/app.js --insecure
```

获取参数：`--timeout`（读取超时，默认 20s）、`--max-bytes`（默认不限）、
`--header`（可重复）、`--insecure`、`--workers`（默认 4）。

### Python

```python
from jsatlas.api import analyze_text, analyze_file, analyze_url, report

# result 是内部完整结果（含证据链），report() 编译成对外那份 JSON
data = report(analyze_file("app.js"))
print(data["apis"][0]["path"], data["secrets"][0]["type"])

# 多个资源合成一份清单
from jsatlas.api import analyze_urls, report_all
data = report_all(analyze_urls(["https://a.com/a.js", "https://b.com/b.js"]))
```

`analyze_*` 返回的是内部结果对象；想要对外那份 JSON，过一遍 `report()`。

### 想直接看一遍"输入什么、输出什么"

```bash
python examples/url_demo.py     # 或 IDE 里右键 Run
```

它会起一个本地 HTTP 服务，用 URL 喂给 JSAtlas，把输入源码和
输出的 `apis` / `secrets` 完整打印出来。不需要外网。

---

## 远程获取的边界

* 只对**你显式给出的 URL** 发起一次 GET。分析过程中提取出的 API 不会被请求。
* 单个 URL 拿不到 → 抛 `FetchError` / CLI 退出码 2，不返回"看起来什么都没有"的空结果。
* 批量时容错：失败的那个不产出结果，成功的照常（退出码 1）。
* 默认校验 TLS 证书，连接 5s / 读取 20s 超时。
* **默认不限字节数**。要自我保护时用 `--max-bytes`，但注意截断会丢掉尾部线索。
* 本模块不做 SSRF 防护 —— 对不可信 URL 请自行评估。

### 关于体积与耗时

JSAtlas **不对源码设任何字符/字节上限**：JScanner2 密钥全链路、
参数 Orchestration、上下文恢复，多大都完整跑。理由很直接——跳过的代价是整段
源码的线索全部丢失，那是漏报，不是优化。

代价是几个 MB 的 bundle 会明显变慢（主要是格式化与 AST 上下文提取）。
真要卡耗时，用这些显式开关自己设，默认一律不限：

| 开关 | 默认 | 作用 |
| --- | --- | --- |
| `--max-bytes` | 不限 | 远程资源字节上限 |
| `--max-context-targets` | 0 = 不限 | 上下文恢复最多处理多少个 API |
| `AnalysisOptions.max_context_bytes` | 5000 | 单个 surface 的上下文字节上限（切片大小，不是源码大小） |

去掉上限后，2.7MB / 6 万行的真实 webpack 产物会从"三条链路直接跳过"变成"全部跑完"，
耗时从毫秒级升到分钟级 —— 慢下来的主要是上下文恢复。这是拿时间换召回，
要卡耗时就用上表的开关。

#### 上下文恢复的缓存优化（B-17）

上下文恢复原本对每个 identifier 都重建作用域链、把整棵子树重扫一遍
（见 `migration-map.md` K-04）。现在对 `_collect_decls_in_subtree` 做了记忆化：

```
120 个 API 样本（2.96MB 文件）
  关缓存   15.9s   递归调用 27,035,270
  开缓存    1.4s   递归调用     26,409      11.0 倍，结果逐条一致
```

做法是纯函数记忆化而非改写算法：原函数逐字保留为 `_collect_decls_in_subtree_uncached`，
新函数只做查表，判定逻辑一行未改；缓存用 `threading.local()`，每次调用入口建、出口清
（`node.id` 是指针地址，跨调用复用会静默命中到另一棵树的节点）。**这是 JSAtlas 第一处偏离上游的
算法层改动**，理由、实测与等价性证明见 `docs/perf-scope-cache.md`。

---

## 输出结构

只有两个顶层块，没有第三样东西：

```json
{
  "apis": [
    {
      "path": "/api/v1/user/detail",
      "method": "POST",
      "params": { "userId": "", "page": "1" },
      "source": "https://example.com/static/app.js"
    }
  ],
  "secrets": [
    {
      "value": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
      "type": "high_entropy_value",
      "risk_level": "Low",
      "test_suggestion": "仅通过 JScanner2 的熵/分词打分命中，未经 AI 复核类型；建议结合变量名与所在函数调用判断是否为有效凭证",
      "source": "https://example.com/static/config.js"
    }
  ]
}
```

字段约定（也是容易踩坑的地方）：

| 字段 | 含义 | 取不到时 |
| --- | --- | --- |
| `path` | 请求路径或完整 URL | 不会为空，否则不输出 |
| `method` | HTTP 方法，大写 | 空字符串。不猜成 GET |
| `params` | 参数名 → 字面量默认值 | **整个键不写**，见下方说明 |
| `source` | 出处，URL 或本地路径 | 纯文本输入为空字符串 |
| `secrets[].type` | 细分类型 | 见下表 |

### `params` 缺失意味着什么（重要）

没提取到参数时**不写 `"params": {}`**，而是整个键不出现。注意语义：

> **缺 `params` = 「未提取到参数」，不是「该接口确认无参数」。**

这不是抠字眼。真实 bundle 里大量调用长这样：

```js
const t = JSON.parse(JSON.stringify(r));
return request({ url: "/acc/repair/deduct/err/list", method: "post", data: t })
```

参数名藏在 Vue 组件的 `data()` 里，`t` 是运行时才有的对象。确定性 ast 解不开这种，
上游 JScanner2 靠 AI 阶段（Level 2/3）读出来——**所以没配 Key、AI 阶段没跑的时候，
这类接口就一定没有 `params` 键**。实测 `app.8bc848d6.js`：2932 个接口里 2917 个没有。

下游处理建议：把缺 `params` 当作「参数未知，需要回去看源码」，不要当作「可以直接无参请求」。
参数值确实时，值仍是空字符串。

`method` 同理保留为空字符串表示「未能确定」，不猜成 GET。
| `risk_level` | High / Medium / Low，按此排序输出 | — |
| `test_suggestion` | 给测试人员的下一步建议（确定性文案，非 AI 生成） | — |

`secrets[].type` 的取值：

| type | 怎么判定出来的 | 风险 |
| --- | --- | --- |
| `high_entropy_value` | JScanner2 统计打分（熵 + 分词双特征），**未经 LLM 复核** | Low |
| 模型复核给出的细分类型（`secret_type`） | 打分命中后再由 LLM 定性 | 按模型判定 |

> **正则密钥链路已按项目决策移除**（`intelligence.upstream_regex`）。
> 上游 `-asir`（手机号 / 邮箱 / 内网 IP / JDBC / 身份证 / 私钥 / Webhook /
> 敏感端点 / SourceMap / 硬编码口令）曾逐字迁移进本项目，在真实 bundle 上
> 43 条命中**全部是误报**：命中的是语言包里的界面文案
> （`password: "Login password"`、`pleaseInputOldPwd: "请输入旧密码"`），
> 甚至把 `oldPwdLabel: "Old password:"` 的**闭合引号**当成密码值的起始引号，
> 输出 `,\n confirmChange:` 这样的源码片段。
> secrets 现在只有计算式来源：行切片 → 熵/分词打分 → AST 上下文 → LLM 复核。
> 代价：手机号、邮箱、内网 IP、JDBC、私钥这类**结构化**凭证不再由 JSAtlas 判定
> （除非它们同时是高熵串并被打分命中）。

### secrets 为空时怎么排查

`secrets: []` 有两种完全不同的含义，别混为一谈：

| 情形 | 表现 |
| --- | --- |
| 根本没候选 | 统计里 `candidates: 0` —— 打分没过阈值，这条链路认为源码里没有可疑串 |
| **有候选、全被 LLM 否掉** | `candidates: N, kept: 0, ai_used: true` —— 打分觉得可疑，模型读完上下文判它们不是密钥 |

规模写在 `statistics.analyzers["intelligence.upstream_secret"]` 里：

```json
{"status": "ok", "candidates": 8, "kept": 0, "ai_used": true}
```

`main.py` 会把这一行直接打印出来。真实 bundle 上常见第二种：候选是
`leniu-icon-kucunpandian`（图标名）、`DEL_ALL_VISITED_VIEWS`（Vuex mutation 名）、
`apiGetNewCangku`（API 函数名）、`ABCDEFGHJKMNPQRSTWXYZ...`（验证码字符集）这类
**高熵但不是秘密**的标识符 —— 打分只看形态，模型看语义，否掉它们正是复核阶段该干的活。

> ⚠️ 注意：候选超过 50 条时（上游 `max_ast_analysis`），只有排序靠前的 50 条
> 会进入复核，**其余直接丢弃**而不是降级返回。这是上游的裁剪顺序，未改动。

多个目标时，结果合并进同一份清单，靠 `source` 区分出处。
正式校验规则见 `schemas/report-v1.schema.json`。

内部模型（surface / point / intelligence / relationship / evidence）依然存在，
用于支撑上下文恢复与回归调试，但不再对外输出 ——
`outputs/report.py` 是唯一承诺给别人看的东西。

**同一份输入跑两次，输出逐字节相同。**

---

## 分析器清单

| name | 维度 | 说明 | 来源 |
| --- | --- | --- | --- |
| `surface.path_candidates` | 攻击面 | AST 字符串字面量 → API 路径 / URL，含请求方法推断 | JSAtlas 新增 |
| `surface.base_url` | 攻击面 | baseURL / apiBase 等配置写入点 | 上游迁移 |
| `context.api_context` | 上下文 | API 所在 wrapper 函数、调用点、参数信号评分 | 上游迁移 |
| `parameters.explicit_params` | 参数 | query 串、路径模板占位符、请求体对象键及其字面量值 | JSAtlas 新增 |
| `parameters.upstream_pipeline` | 参数 | **JScanner2 Orchestration 全链路**：黑名单 → AST 上下文 → Level 2 判定 → Level 3 取值 | 上游迁移 |
| `intelligence.upstream_secret` | 密钥 | **JScanner2 Orchestration 全链路**（对应上游 `-asia`）：HTML 剥离 → 格式化 → 行切片 → 熵/分词打分 → AST 上下文 → LLM 复核 | 上游迁移 |

密钥链路在上游有两条独立开关（`-asir` 正则、`-asia` 全链路），JSAtlas **只保留 `-asia`**：
正则那条在真实 bundle 上 43 条命中全是误报，已整体移除（见上）。
判定逻辑与上游一致，JSAtlas 只在命中之后补类型、风险等级与建议文案。

### 已经原样搬过来的 JScanner2 模块

迁移方式是**逐字复制后只替换 import 接缝**，不是重写。
`tests/unit/test_upstream_parity.py` 会剥掉 import 后与上游逐字节比对，
任何对逻辑体的改动都会被测试拦下。

| 上游 | 落到 | 用途 |
| --- | --- | --- |
| `processor/analysis/params/params_scan.py` | `analyzers/parameters/upstream_params.py` | `AISecurityAuditor`：Level 1~3 参数识别 |
| `processor/analysis/secret/secret_scanner.py`（编排段） | `analyzers/intelligence/upstream_secret_scanner.py` | `SensitiveInfoScanner` / `LLMSecretVerifier` |
| `processor/analysis/prompts/prompts.py` | `analyzers/prompts/` | 7 条通用提示词 |
| `processor/analysis/secret/prompt.py` | `analyzers/intelligence/secret_prompt.py` | 密钥复核提示词 |
| `infra/ai_client.py` | `llm/client.py` | AIHubClient（多模型故障转移） |
| `processor/js/format/js_formatter.py` | `parsing/preprocess.py` | `format_code`：jsbeautifier / prettier / 应急分行 |
| `config/scanner_rules.py` | `parsing/scanner_rules.py` | 黑名单与关键词规则集 |
| `infra/utils.py:remove_html_tags` | `utils/html.py` | HTML 包裹内容剥离 |
| `request_executor._parse_params_string` | `utils/params_string.py` | 参数串 → 字典 |

### AI 怎么用

AI 对应上游 `-asia` 那条产线，**默认开启**，没有开关：

```bash
export JSATLAS_LLM_API_KEY=sk-xxx
python -m jsatlas app.js
```

默认就会走参数 Level 2/3 与密钥 LLM 复核。只有取不到模型（没配 Key 或缺 SDK）
时才会降级：链路照跑，结果带 `ai_verified=False` / `ai_analyzed=False`，
不会被当成模型已确认的结论 —— 这是兜底，不是开关。

`param_pre_filter`（要不要送 AI 的省钱闸门）与 `line_prefilter` 也已迁移，
上游同样是 `-asia` 打开后才生效。

### 去重策略

只做**单次运行内去重**，用朴素 `set`（`utils/dedup.py`），不用布隆过滤器：

- 单次分析的数据量撑不起 Bloom 的规模价值，而 Bloom 的假阳性会把"漏报"
  变成一个概率问题；
- 不落盘、不跨运行复用 —— 上游在 `Result/*.bloom` 复用是"长期扫描任务"的语义，
  JSAtlas 是"一段 JS 进、一份 JSON 出"，跨轮复用只会让上一轮的结果抑制这一轮。

每次 `scan()` 开头重置集合，因此同一份输入重复跑结果一致。

---

## 测试

```bash
python -m pytest                      # 全量
python -m pytest tests/unit -q        # 只跑单测
```

与上游 JScanner2 的对拍：

```bash
python tests/regression/parity_with_upstream.py

# 加跑大样本（耗时较长）
JSATLAS_BIG_SAMPLE=/path/to/app.js python tests/regression/parity_with_upstream.py
```

对拍加载的是**上游生产实现**，逐字段比对
`found / api_url / wrapper_code / caller_codes / param_score`。
上游根目录可用 `JSCANNER2_ROOT` 覆盖，找不到时自动跳过（不判失败）。

---

## 文档

| 文件 | 内容 |
| --- | --- |
| [`PROJECT_SPEC.md`](PROJECT_SPEC.md) | 项目说明书（目标、边界、架构、阶段、验收标准） |
| [`docs/architecture.md`](docs/architecture.md) | 分层、数据流、硬约束、扩展点 |
| [`docs/migration-map.md`](docs/migration-map.md) | 迁移映射：来源、改动、行为变化、已知限制 |
| [`examples/`](examples) | 示例输入与输出 |

---

## 边界：JSAtlas 首期不做什么

* 不自主规划和执行完整渗透测试；
* 不替代 AI Agent 选择攻击路径；
* **默认不向提取到的 API 发起请求**；
* 不把提取结果直接认定为漏洞；
* 不强制依赖大语言模型或某个 Agent 框架；
* 不继承上游的扫描调度、SQLite 与报告系统。
