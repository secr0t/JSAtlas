# `_collect_decls_in_subtree` 声明列表缓存

状态：**已实施**（2026-10-09）。落地代码见 `src/jsatlas/analyzers/context/context_extractor.py`，
等价性与隔离性由 `tests/unit/test_scope_cache.py`（4 项）守住。

改动小结：

* 原函数逐字保留为 `_collect_decls_in_subtree_uncached`，**一行未改**；
* 新 `_collect_decls_in_subtree` 只是查表/记账外壳，判定逻辑未动；
* 缓存载体是 **`threading.local()`**（不是裸全局），由 `_extract_multiple_apis_from_bytes`
  入口建、出口 `try/finally` 清空，生命周期严格等于一次调用一棵树，且天然线程隔离。

---

## 1. 问题

`context_extractor.py` 的变量查找链路：

```
_find_var_value_node(var_name, usage_node)
   └─ _build_scope_chain(usage_node)          # 从使用点向上走到 program
        └─ 对每个作用域边界节点调用 _collect_decls_in_subtree(scope_node)
             └─ 递归扫整棵子树，捞出所有 var/let/const/赋值
```

关键性质：`_collect_decls_in_subtree(node, decls)` **只依赖 `node` 自己**
（它甚至没有 `code_bytes` 参数），但每次查变量都会被调用一次。
在一个 webpack 产物里，每个 API 会触发上万次变量查找，
而每次查找都要把外层的 webpack 模块函数、乃至整个 `program` 子树重扫一遍。

复杂度 ≈ `API 数 × 函数内标识符数 × 子树大小`，且**全程没有任何缓存**。

---

## 2. 方案

只对**纯函数**做记忆化，不动任何判定逻辑：

```python
_DECL_CACHE = threading.local()      # per-thread: {"map": {node.id -> List[Node]}}


def _collect_decls_in_subtree(node: Node, decls: List[Node]):
    cache = getattr(_DECL_CACHE, "map", None)   # 未启用时退化为原实现
    if cache is not None:
        hit = cache.get(node.id)
        if hit is not None:
            decls.extend(hit)                   # 命中：直接用
            return
    buf: List[Node] = []
    _collect_decls_in_subtree_uncached(node, buf)   # 原实现，逐字保留
    if cache is not None:
        cache[node.id] = buf
    decls.extend(buf)
```

入口/出口：

```python
def _extract_multiple_apis_from_bytes(code_bytes, target_apis, trace=None, parser=None):
    _DECL_CACHE.map = {}
    try:
        return _extract_multiple_apis_from_bytes_uncached(...)
    finally:
        _DECL_CACHE.map = None
```

原函数改名为 `_collect_decls_in_subtree_uncached`，逐字保留，
新函数只做「查表 / 记账」，**判定逻辑一行不改**。

### 为什么结果一定不变

`_collect_decls_in_subtree` 是纯函数：

* 唯一输入是 `node`，不读 `code_bytes`、不读全局变量、不依赖调用时刻；
* 唯一副作用是往传入的 `decls` 里 append；
* 调用方（`_find_var_value_node` / `_is_declared_in_function`）只遍历，不修改。

因此「同一个 node → 同一份声明列表」恒成立，缓存只是省掉重复计算。
DFS 顺序也一致，列表顺序不变。

### 缓存必须每文件重建（硬性要求）

`node.id` 是 tree-sitter 内部的**指针地址**。
如果缓存是模块级全局且长期存活：

* 旧 `Tree` 被回收后，新 `Tree` 可能分配到相同地址 → **命中到另一个文件的声明**，
  结果是静默错误，不是报错；
* 缓存持有 `Node` 会连带把整棵 `Tree` 钉在内存里，批量扫描时只增不减。

因此缓存必须在 `_extract_multiple_apis_from_bytes` **入口创建、出口清空**
（`try/finally`），生命周期严格等于一次调用、一棵树。

实际实现用的是 **`threading.local()`** 而不是裸全局字典：

* 每次调用在入口重建一张空表，出口置 `None`（不是留空 dict），
  这样"缓存未激活"是显式状态，误用会退化而非错位；
* thread-local 保证将来并行化时各线程各存一份，不需要显式加锁。

注意 `_collect_decls_in_subtree_uncached` 的递归内部调用的仍是**带缓存**的表层函数，
所以中间节点也进缓存 —— 这也是缓存条目数（约 2 万）多于边界节点数（10,283）的原因，
属预期行为，且已被等价性测试覆盖。

---

## 3. 实测

### 3.1 落地前：运行时打补丁探索


| 样本 | 递归调用次数 | 耗时 | found |
| --- | --- | --- | --- |
| 40 个 API · 原始 | 8,641,304 | 5.6 s | 39 |
| 40 个 API · 加缓存 | 15,462 | 0.9 s | 39 |
| 150 个 API · 原始 | 33,640,892 | 32.3 s | 133 |
| 150 个 API · 加缓存 | 30,071 | 2.6 s | 133 |

### 3.2 落地后：仓库代码实测（2026-10-09）

同一份文件 `tests/app.8bc848d6.js`，样本 120 个 API，跑真实代码路径
（关缓存 = 把表层函数换成 `_uncached` 版）：

| | 耗时 | 递归调用 | found |
| --- | --- | --- | --- |
| 关缓存 | **15.9 s** | 27,035,270 | 115 |
| 开缓存 | **1.4 s** | 26,409 | 115 |

* 加速 **11.0 倍**，递归调用 **2700 万 → 2.6 万**（1024 倍压缩）；
* `结果逐条一致: True`；
* 线性外推到 1779 个 API：**236 s → 21 s**。用户实际观察到的 271.8 s，
  对应落到 **20~30 s 量级**。

参考：该文件的作用域边界节点共 10,283 个（`program` 1 + 函数 10,282）。
原始实现对这 1 万个节点反复重扫了三千万次。

---

## 4. 对正常使用的影响

| 维度 | 影响 |
| --- | --- |
| 输出结果 | **无变化**。纯函数记忆化，已用真实文件逐条比对证明 |
| 确定性 | **无变化**。不引入随机、不引入概率结构（不同于布隆过滤器） |
| 速度 | 大文件 × 多 API 场景 **11 倍**提升；小文件无感（本来就是毫秒级） |
| 内存 | 单次调用内多出约 2 万条小列表，可忽略；调用结束 `map=None` 即释放 |
| 并发 | `threading.local()`，天然 per-thread，无需加锁 |
| API / CLI | **无变化**，不需要新参数，默认开启 |
| 与上游一致性 | 这是该文件第一处算法层偏离，见下 |

## 5. 代价与补偿：与上游不再逐字一致

`context_extractor.py` 原先与上游 `processor/js/context/context_extractor.py`
剥掉 import 后的差异只有 3 处，且**都不在热点函数上**：

1. 顶部一段迁移说明注释；
2. `_find_callers_of_function` 的 docstring 扩写；
3. 解析器可注入（`parser=None` 时行为与上游完全一致）。

加缓存后新增第 4 处，且是第一个**算法层偏离**。
`migration-map.md` 里该文件的标注已改为「逐字迁移 + 1 处缓存（B-07）」。

已做的补偿：

* ✅ 原函数以 `_uncached` 后缀逐字保留，便于 diff 与反向同步；
* ✅ `tests/unit/test_scope_cache.py` 守住三条边界：
  * `test_cached_equals_uncached` — 同一份输入 cached / uncached 输出必须逐条相等；
  * `test_cache_cleared_after_call` — 每次调用后缓存必须清空；
  * `test_cache_isolated_across_calls` — 连续两次不同输入互不污染；
  * `test_cache_produces_hits` — 缓存确实命中（防止改成永远空表还"通过"）。

也就是说「优化没有改变行为」是被测试守住的，不依赖人记住。

未做的取舍：**不加 CLI 开关**（如 `--no-decl-cache`）。有了等价性测试，
开关的价值小于它带来的组合复杂度；需要对照时直接在 Python 里替换
`ce._collect_decls_in_subtree = ce._collect_decls_in_subtree_uncached` 即可。

---

## 附：复现命令

```bash
# 1) 等价性与隔离性
pytest tests/unit/test_scope_cache.py -q

# 2) 加速实测（120 个 API，约 18 秒）
python - <<'PY'
import re, time
import jsatlas.analyzers.context.context_extractor as ce

CACHED = ce._collect_decls_in_subtree          # 默认实现（带缓存）
UNCACHED = ce._collect_decls_in_subtree_uncached

js = open('tests/app.8bc848d6.js', encoding='utf-8', errors='replace').read()
paths = list(dict.fromkeys(re.findall(r'["\'](/[a-zA-Z0-9_/\-]{2,})["\']', js)))[:120]

results = {}
for label, fn in (("uncached", UNCACHED), ("cached", CACHED)):
    ce._collect_decls_in_subtree = fn
    t = time.perf_counter()
    r = ce.extract_multiple_apis_from_raw_code(js, list(paths))
    print('%-9s %6.1fs found=%d' % (label, time.perf_counter() - t,
          sum(1 for v in r.values() if v.get('found'))))
    results[label] = r

ce._collect_decls_in_subtree = CACHED
print('结果逐条一致:', results["cached"] == results["uncached"])
PY
```

> 注：上面这段演示直接替换模块级函数名；真实调用不要这么做，默认入口已是带缓存版本。
