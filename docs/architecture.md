# JSAtlas 架构说明

## 1. 分层

```text
输入层   inputs/source.py        文本 / 本地文件（核心，无网络依赖）
         inputs/remote.py        远程 URL（可选适配器；requests 缺失则退 urllib）
           |
解析层   parsing/parser.py      tree-sitter 单例，可注入
         parsing/location.py    统一位置模型（byte 区间为权威值）
           |
分析层   analyzers/surfaces     攻击面：路径候选、baseURL 写入点
         analyzers/parameters   参数：信号评分、显式参数提取
         analyzers/context      上下文：wrapper 函数、调用点、参数信号
         analyzers/intelligence 密钥：JScanner2 统计打分 + LLM 复核（正则链路已移除）
           |
流水线   pipeline/context       分析上下文（唯一的写入口：add_xxx）
         pipeline/registry      分析器注册表
         pipeline/relationship  关系构建
         pipeline/orchestrator  编排
           |
输出层   output/report.py       内部结果 → 对外报告（apis + secrets）
         output/serializer      to_dict / to_json / write_json
         output/validator       内置结构校验 + 可选 JSON Schema 校验
```

**内部模型与对外契约分离。** 内部保留 surface / point / intelligence /
relationship / evidence 五类实体，用来支撑上下文恢复和回归调试；
对外只有 `output/report.py` 编译出来的那两个块。改动那里才算改契约。

## 2. 数据流

一次分析只走这一条路径：

```text
analyze_text(code)
  → build_target(code)              稳定 source_id（内容摘要派生）
  → parse_bytes(code)               AST；失败时 tree=None，不抛异常
  → AnalysisContext                 承载全部可变状态
  → 逐个分析器 run(ctx)             单个分析器抛错不影响其余
  → build_relationships(ctx)        建边（推断性边标 low）
  → AnalysisResult                  内部完整结果（不直接对外）
  → output/report.build_report      编译成 {"apis": [...], "secrets": [...]}
```

最后一步是输出的唯一出口。它做四件事：

1. **只收真正的接口**：baseURL 写入点、纯域名、字符串拼接的后续片段
   （`'/a/b/' + id + '/delete'` 里的 `/delete`）都不进 apis；
2. **参数拍平成 dict**：字面量常量保留，`page: page` 这类写成空字符串；
3. **只收 JScanner2 判定的密钥**：以 `attributes.method` 为闸门，
   非 `jscanner2.*` 的情报不会混进 secrets；
4. **按 High → Medium → Low 排序 secrets**，下游从第一条开始处理即可。

## 3. 三条硬约束

### 3.1 核心分析无副作用

分析器不得：发起网络请求、写数据库、写文件、依赖全局扫描状态。
可做的只有：读 `ctx`、调 `ctx.add_xxx`、`ctx.warn/error`。

这条约束带来的直接收益是：任何一个分析器都能单独单测，
不需要先"启动一次扫描"。

### 3.2 确定性结果与 AI 结论必须可区分

每个 intelligence 都带 `detector` 字段，取值
`regex` / `statistical` / `ast` / `ai`。前三类是确定性结果，
`ai` 是模型输出 —— **两者在输出里永远可区分**，不允许混为一谈。

AI 是**默认能力**，`AnalysisOptions.enable_ai` 默认 `True`，密钥 LLM 复核与
参数 Level 2/3 默认都跑。取不到模型时各分析器自行降级，并打上
`ai_verified=False` / `ai_analyzed=False`，让两类结论仍然可区分。
这是兜底路径，不是开关 —— CLI 里没有 `--enable-ai`。

### 3.3 关联必须有依据，猜的必须标 low

`confidence` 只有三档：

* `high` —— 有确定性证据（AST 结构、强特征正则）；
* `medium` —— 形态命中但未完全确认；
* `low` —— 启发式推断。

`api_uses_base_url`、`intel_near_api` 这两类关系**固定为 low**，
并在 `basis` 里写明"推断，未证明"。不在没有证据时凭空建边：
`add_relationship` 在任一端 ID 为空时直接返回 `None`。

## 4. 稳定 ID

规则见 `src/jsatlas/models/ids.py`。要点：

* 前缀标类型：`src_` / `srf_` / `pnt_` / `itl_` / `rel_` / `evd_`；
* 值 = `SHA-1(语义字段)[:12]`，同输入同分析器必得同 ID；
* 不用 uuid、不用计数器、不依赖遍历顺序；
* 同一语义自动收敛到同一 ID —— 去重因此天然生效，不需要额外去重模块。

## 5. 扩展点

| 想加什么 | 改哪里 |
| --- | --- |
| 新的提取能力 | 写一个 `Analyzer` 子类，`register(实例)`；加进 `orchestrator._DEFAULT_ORDER` |
| 新的密钥规则 | 判定方法不另行发明：只在 JScanner2 的计算式链路里加（打分特征 / LLM 复核提示词）。正则链路 `secret_regex.py` / `upstream_regex.py` 已按决策移除 |
| **改动对外输出字段** | `output/report.py` + `schemas/report-v1.schema.json`，两处必须同步 |
| 新的语言（TS / JSX） | `parsing/parser.set_parser(...)`；分析器不用改 |
| AI 增强 | 新分析器把 `dimension` 设为 `"ai"`；`enable_ai` 默认 True，只在显式关闭时跳过 |
| 远程资源 | `inputs/remote.py` 已落地（URL → `Source`），核心层无需改动 |
| 浏览器动态资源 | 后续：同样只加一个 `inputs/` 适配器，输出 `Source` |

## 6. 远程输入的边界

`inputs/remote.py` 是可选适配器，`import jsatlas.api` 不会触发任何网络代码。

| 约束 | 取值 | 理由 |
| --- | --- | --- |
| 只请求显式给出的 URL | 一次 GET | 绝不请求分析过程中提取出的 API |
| 依赖降级 | requests → urllib | 核心能力不因缺第三方库而不可用 |
| 连接 / 读取超时 | 5s / 20s | 连不上要快速失败，读大 bundle 要给足时间 |
| 单资源上限 | **默认不限**（`--max-bytes` 可设） | 截断会让尾部接口/密钥整体消失，是漏报不是保护 |
| 重定向 | 最多 5 跳，记 `final_url` | 防止重定向环 |
| TLS 校验 | 默认开，`--insecure` 才关 | 默认安全 |
| 并发 | `from_urls(..., max_workers=4)` | 只并发获取，分析仍串行（CPU 密集） |

失败语义：单个 URL 失败抛 `FetchError`（CLI 退出码 2）；
批量时失败项带 `Source.error` → `statistics.errors`，其余照常产出（CLI 退出码 1）。

## 7. 失败处理

| 情况 | 行为 |
| --- | --- |
| 空输入 | 正常返回，所有列表为空，输出仍通过 Schema 校验 |
| 语法错误 | tree-sitter 容错解析，`statistics.parsed=False` + 告警，其余分析照跑 |
| tree-sitter 不可用 | `parse_bytes` 返回 None，依赖 AST 的分析器跳过并告警，文本类分析器照跑 |
| 单个分析器抛异常 | 记进 `statistics.errors`，其余分析器继续 |
| 源码体积 | **不做上限**：多大就分析多大。需要自保时用 `MAX_SOURCE_BYTES` / `--max-bytes` |
| URL 返回 4xx/5xx | 抛 `FetchError`，不产出"看起来什么都没有"的空结果 |
| 远程资源体积 | 同上，默认不限；显式设了 `max_bytes` 才流式截断并记 `attributes.truncated_at_bytes` |
| content-type 明显非 JS | 照常分析，但在 `statistics.warnings` 提示结果可能无意义 |
