# JSAtlas 项目说明书

**版本：** v0.1
**阶段：** 新项目初始化与核心代码迁移
**上游项目：** JScanner2
**核心定位：** JavaScript Security Intelligence Engine

---

## 1. 项目目标

JSAtlas 是一个 JavaScript 安全情报提取引擎，负责从 JavaScript 源码及相关资源中提取尽可能多的安全相关信息，并以统一、可追溯、机器可消费的结构化数据输出。

JSAtlas 是 JScanner 演进过程中形成的新项目，不是对 JScanner2 的简单改名，也不是对原项目的完整复制。

新项目的核心目标是将已经积累的 JavaScript 分析能力重新组织成独立、可复用的基础能力，为安全测试人员、其他安全工具以及 AI Agent 提供可靠的数据输入。

### 1.1 核心分析维度

**Surface：攻击面**

* API、Endpoint、请求路径。
* 请求方法及调用位置。
* 可识别的外部交互入口。

**Point：参数与输入点**

* Query、Path、Body、Header 等参数。
* 参数值、表达式及来源。
* 参数与 API 的归属关系。
* 参数相关的代码上下文。

**Intelligence：安全情报**

* 疑似敏感信息和凭证。
* 内部地址、环境配置及调试线索。
* 认证相关线索。
* 其他有助于后续安全测试的信息。

**Evidence：分析证据**

* 源文件及资源来源。
* 代码位置和相关片段。
* 提取依据。
* 发现之间的关联关系。

项目的价值不仅是列出发现，还要尽可能恢复发现之间的关系，让下游程序能够据此开展进一步分析。

## 2. 项目边界

### 2.1 JSAtlas 负责

* JavaScript 源码解析。
* API 和参数提取。
* 参数上下文恢复。
* 敏感信息及安全相关线索识别。
* 发现之间的关系构建。
* 证据管理、去重、结果归并。
* 统一 JSON 输出。
* 可选的远程 JavaScript 获取和 AI 辅助分析。

### 2.2 JSAtlas 首期不负责

* 自主规划和执行完整的渗透测试。
* 替代 AI Agent 选择攻击路径。
* 默认向提取到的 API 发起请求。
* 将提取结果直接认定为漏洞。
* 强制依赖大语言模型或某个 Agent 框架。
* 直接继承原项目全部的扫描调度、数据库和报告系统。

JSAtlas 输出的是安全情报和分析依据，不是未经验证的漏洞结论。

## 3. 总体架构

```text
输入层
  ├── JavaScript 源码文本
  ├── 本地 JavaScript 文件
  └── 远程 URL / 动态资源（后续扩展）
             |
             v
      Source Manager
             |
             v
       JS Parser / AST
             |
             v
    Analysis Orchestrator
             |
     +-------+---------+
     |       |         |
   Surface  Parameter  Intelligence
   Analyzer Analyzer  Analyzer
     |       |         |
     +-------+---------+
             |
             v
      Context Recovery
             |
             v
    Relationship Builder
             |
             v
      Evidence Registry
             |
             v
      Result Aggregator
             |
             v
       Schema Validator
             |
             v
        JSON Output
```

架构必须遵循以下原则：

1. **核心分析与资源获取分离。** 本地源码分析不要求网络或浏览器。
2. **各分析器职责独立。** API、参数和敏感信息识别可以分别测试。
3. **上下文与关系是一等能力。** 不只输出孤立的 API 或参数列表。
4. **确定性分析优先。** AST、语法结构和算法负责基础提取，AI 作为可选增强。
5. **证据可追溯。** 每个重要发现尽可能指向源码位置和分析依据。
6. **核心接口可独立调用。** 不要求必须启动完整扫描流程。
7. **先建立最小架构，再逐步扩展。** 避免过度设计和一次性迁移全部历史代码。

## 4. 数据模型

### 4.1 对外输出契约：`apis` + `secrets`

对外唯一承诺的输出形态。字段少、可直接消费，不含内部实体与调试信息。

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
      "value": "example-secret-value",
      "type": "possible_api_key",
      "risk_level": "High",
      "test_suggestion": "建议进一步确认该凭证的用途及有效性",
      "source": "https://example.com/static/config.js"
    }
  ]
}
```

| 字段 | 说明 | 取不到的取值原则 |
| --- | --- | --- |
| `apis[].path` | 可请求的接口路径或完整 URL | —— |
| `apis[].method` | 请求方法 | **空字符串**，不猜 GET/POST |
| `apis[].params` | 参数名 → 字面量默认值 | 值不确定时**空字符串**，键仍保留 |
| `apis[].source` | 来源（URL 或本地路径） | 纯文本输入为空字符串 |
| `secrets[].type` | 细分类型：`aws_access_key` / `jwt` / `jdbc_uri` / `private_ip` / `high_entropy_value` 等 | —— |
| `secrets[].risk_level` | `High` / `Medium` / `Low` | —— |
| `secrets[].test_suggestion` | 给下游的处置建议 | —— |

约束：

* `secrets` **只收 JScanner2 计算式链路判定的条目**（内部标记 `jscanner2.statistical`
  / `jscanner2.pipeline`），不自造并行规则，保证能力边界不会被悄悄拓宽。
  正则链路（`jscanner2.regex`）已移除：真实 bundle 上其 43 条命中全是语言包文案误报。
* 同一值重复命中时保留风险等级更高的那条，并按 High → Medium → Low 排序，
  下游从第一条开始处理即可。
* `base_url` 是前缀配置、纯域名不可单独请求，两者都不进 `apis`。
* 多个输入合并为**一份**报告（不是数组），逐资源追加后整体排序。

校验规则见 `schemas/report-v1.schema.json`。

### 4.2 内部分析结果（不在对外契约中）

编排器在分析过程中构建 `target` / `surfaces` / `points` / `intelligence` /
`relationships` / `evidence` / `statistics` 七类实体，用于保留源码位置、
提取依据和实体关联，**不出现在对外输出里**，供调试、回归比对与后续能力扩展使用。

每种实体有稳定 ID（由"类别 + 关键内容"派生，同输入必同 ID）。
无法确认的关联必须允许为空或标记为未知，不能为填满结果而猜测。

## 5. 目标目录结构

```text
JSAtlas/
├── README.md
├── PROJECT_SPEC.md
├── pyproject.toml
├── src/
│   └── jsatlas/
│       ├── __init__.py
│       ├── cli.py
│       ├── api.py
│       ├── inputs/
│       ├── parsing/
│       ├── analyzers/
│       │   ├── surfaces/
│       │   ├── parameters/
│       │   ├── context/
│       │   └── intelligence/
│       ├── models/
│       ├── pipeline/
│       ├── output/
│       └── utils/
├── schemas/
│   └── report-v1.schema.json
├── tests/
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   └── regression/
├── docs/
│   ├── architecture.md
│   └── migration-map.md
└── examples/
    ├── input.js
    └── output.json
```

该结构是目标结构，不要求一次性创建所有空模块。每个目录应随着对应能力的实现逐步建立。

## 6. JScanner2 代码迁移方案

### 6.1 迁移总原则

迁移经过验证的能力，而不是原项目的目录结构。

迁移前必须确认：

* 模块的真实调用入口。
* 输入、输出和副作用。
* 对原项目配置、全局状态、数据库及调度器的依赖。
* 是否能够独立测试。
* 应直接复用、重构还是重新实现。

### 6.2 第一批迁移审计清单

| JScanner2 候选路径 | 对应能力 | 处理策略 |
| --- | --- | --- |
| `processor/js/context/context_extractor.py` | 上下文提取 | 优先审计，拆分核心逻辑与旧流程依赖 |
| `processor/js/context/param_scoring.py` | 参数上下文评分 | 优先审计，迁移后建立独立测试 |
| `processor/js/context/base_url_extractor.py` | Base URL 提取 | 评估是否纳入攻击面分析模块 |
| `processor/js/context/js_line_extractor.py` | 源码行定位 | 评估复用价值，统一证据位置模型 |
| `processor/analysis/api/api_scan.py` | API 分析 | 审计后迁移必要的提取逻辑 |
| `processor/analysis/params/params_scan.py` | 参数分析 | 优先审计，拆分提取与扫描调度 |
| `processor/analysis/params/param_pre_filter.py` | 参数预过滤 | 验证实际效果后决定迁移 |
| `processor/analysis/secret/secret_scanner.py` | 敏感信息识别 | 优先审计算法和数据流 |
| `processor/analysis/secret/js_sensitive_rex.py` | 正则识别规则 | 逐项评估，不直接整体搬迁 |
| `crawler/httpx_crawler.py` | HTTP 资源获取 | 后续迁入独立输入适配层 |
| `crawler/browser_crawler.py` | 浏览器资源获取 | 后续迁移，不能成为核心分析的强制依赖 |
| `infra/dedup.py` | 去重 | 审查是否适用于新的实体模型 |
| `infra/bloom.py` | 布隆过滤器 | 仅在规模和性能需求证明必要时迁移 |

这是一份审计清单，不代表上述文件已被逐个分析或确认可以直接迁移。

> **审计结果见 [`docs/migration-map.md`](docs/migration-map.md)。**

### 6.3 首期不迁移的功能

* 原有完整扫描入口和任务调度流程。
* 与旧 SQLite 数据模型紧密耦合的业务逻辑。
* 原有报告、通知和 UI 相关流程。
* 未证明实际价值的 API 路径预测功能。
* 默认自动请求提取参数的执行逻辑。
* 不能适应新数据模型的旧版结果对象。

不迁移并不意味着这些功能没有任何价值，而是它们不应决定新项目第一阶段的架构。

### 6.4 单模块迁移流程

1. 检查源代码及调用关系。
2. 写明该模块要解决的问题。
3. 识别其依赖和副作用。
4. 定义新项目中的输入输出接口。
5. 提取可独立调用的核心逻辑。
6. 编写单元测试。
7. 使用原有样本执行回归对比。
8. 记录行为变化、已知限制及来源。
9. 验收通过后再迁移下一模块。

严禁先复制整个旧目录，再通过大量临时兼容代码修复依赖。

## 7. 实施阶段

### Phase 0：代码审计

* 梳理 JScanner2 相关代码和依赖。
* 确定核心提取逻辑与旧扫描流程的边界。
* 建立迁移清单。
* 收集可复现的测试样本。

交付物：`docs/migration-map.md`。

### Phase 1：初始化 JSAtlas

* 创建项目包结构。
* 定义基础数据模型和稳定 ID 规则。
* 定义输入、分析器和输出接口。
* 建立 JSON Schema。
* 建立测试框架和日志规范。

验收：源码文本可以进入核心流程，输出符合 Schema 的 JSON，即使当前尚未集成真实分析器。

### Phase 2：迁移基础分析能力

按顺序迁移：

1. JavaScript 解析与源码位置管理。
2. API / Endpoint 提取。
3. 参数提取。
4. 参数上下文恢复。
5. 敏感信息识别。
6. 关系和证据构建。
7. 去重、聚合与标准化输出。

每个模块必须能够独立测试。

### Phase 3：接入资源获取

* 支持本地文件和远程 URL。
* 需要时接入浏览器动态资源获取。
* 设置超时、并发、资源大小和错误处理机制。
* 不默认对提取出的 API 发起请求。

### Phase 4：可选扩展

* 接入 AI 语义分析适配层。
* 提供稳定的 Python API 和 CLI。
* 根据实际需求评估 MCP 或其他集成方式。
* 不在核心模块中绑定具体 Agent 框架。

## 8. 验收标准

| 验收项 | 标准 |
| --- | --- |
| 架构 | 输入、解析、分析、关联和输出职责分离 |
| 可调用性 | 核心分析可独立调用，不要求启动完整扫描流程 |
| 数据结构 | 输出通过版本化 JSON Schema 校验 |
| 证据 | 重要发现尽可能保留源码位置和依据 |
| 关联 | API、参数和情报支持显式关联 |
| 稳定性 | 空输入、语法错误和部分解析失败可以被正确处理 |
| 可测试性 | 核心分析器具备单元测试和回归样本 |
| 可扩展性 | AI、远程资源获取等能力可以独立启用或关闭 |
| 迁移质量 | 每个迁移模块均有来源记录和行为对比 |

首版不预先承诺未经测试的召回率。应先建立基准样本集，再分项评估 API、参数、上下文和敏感信息的召回率与误报率。

## 9. 开发约束

* 不为迁移而迁移。
* 不在核心分析器中混入扫描调度逻辑。
* 不将 AI 输出与确定性分析结果混为一谈。
* 不以孤立参数列表代替上下文恢复。
* 不在没有测试依据时宣称召回率提升。
* 不为追求抽象而提前实现复杂插件体系。
* 迁移过程中保留必要的许可证和代码来源记录。
* 每个阶段完成后，项目都应处于可运行、可测试的状态。

## 10. 第一阶段最终交付

第一阶段完成时，JSAtlas 应具备：

1. 独立的项目目录与基础配置。
2. 清晰的模块职责和调用接口。
3. 统一的基础数据模型及 JSON Schema。
4. 可复用的源码解析和核心分析器接口。
5. 第一批经过测试的 JScanner2 迁移能力。
6. 自动化测试与回归样本。
7. 完整的代码迁移记录。

**第一阶段的目标不是立刻复制 JScanner2 的全部功能，而是建立一套正确的架构，并让第一批高价值能力在新架构下独立运行。**
