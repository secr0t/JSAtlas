"""单次运行内的朴素集合去重（不用布隆过滤器）。

上游用 `infra/bloom.py` 的 `DiskBloomFilter` 在 `Result/*.bloom` 落盘，
跨进程、跨班次复用 —— 那是"长期扫描任务"的语义。

JSAtlas 的定位是"给一段 JS，出一份 JSON"，所以去重策略明确为三条：

* **只做单次运行内去重**：同一次分析里重复出现的候选 / 输出行只保留一条。
* **不做跨运行去重**：不落盘、不读上一轮状态，避免上一轮的结果抑制本轮，
  也避免在用户目录里留下 `Result/*.bloom` 这种副作用文件。
* **不用布隆过滤器**：单次分析的数据量（几百到几万条字符串）撑不起 Bloom 的
  规模价值，而 Bloom 的假阳性会把"漏报"变成一个概率问题。这里直接用 Python
  `set`，精确、无假阳性，内存开销在这个量级上可以忽略。

接口与上游 `infra.bloom.DiskBloomFilter` 保持一致（`contains / add / close`），
因此迁移过来的上游代码不需要为去重改写任何一行判断逻辑。
`capacity` / `error_rate` 只是保留形参以兼容上游调用处，内部不使用。
"""

from __future__ import annotations

from typing import Set


class MemoryDedup:
    """进程内精确集合去重，语义等价于"这一轮见过的就不再重复处理"。"""

    def __init__(self, name: str = "", capacity: int = 0, error_rate: float = 0.001):
        # capacity / error_rate 仅用于兼容上游 DiskBloomFilter 的调用签名，
        # 内存实现用精确集合，不存在"预估容量"和"误判率"这两个概念
        self.name = name
        self.capacity = capacity
        self.error_rate = error_rate
        self._seen: Set[str] = set()

    def contains(self, value: str) -> bool:
        return value in self._seen

    def add(self, value: str) -> None:
        self._seen.add(value)

    def close(self) -> None:
        """清空集合。上游这里是"关闭落盘文件句柄"。"""
        self._seen.clear()

    def clear(self) -> None:
        self._seen.clear()

    def __contains__(self, value: str) -> bool:
        return value in self._seen

    def __len__(self) -> int:
        return len(self._seen)


__all__ = ["MemoryDedup"]
