"""输入适配层：把各种来源变成统一的源码文本。

边界（PROJECT_SPEC 3 / 7）：
* 本地文件与文本输入是核心能力，**不要求网络**；
* 远程 URL 由同层 `remote.py` 负责，是可选适配器，不是核心分析的依赖；
* 浏览器动态资源属于后续扩展，这里不预留半成品接口。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# 单个资源的字节上限。**默认 0 = 不限制。**
# JSAtlas 的契约是"给一段 JS 出情报"，输入多大就分析多大 ——
# 截断意味着尾部接口/密钥整体消失，那是漏报，不是保护。
# 常量保留下来是为了让调用方能自己加闸（批量跑时防内存打爆），
# 传 0 或负数表示不限。
MAX_SOURCE_BYTES = 0

_ENCODINGS = ("utf-8", "utf-8-sig", "gbk", "latin-1")

#: 合法的输入类型。url 由 remote.py 产出。
INPUT_TYPES = ("text", "file", "url")


@dataclass
class Source:
    """一份待分析的 JavaScript 源码。"""

    text: str
    input_type: str  # text | file | url
    origin: str = ""
    encoding: str = "utf-8"
    truncated: bool = False
    # 来源元信息（HTTP 状态码、content-type、最终 URL、耗时等），会并入 target.attributes
    attributes: Dict[str, Any] = field(default_factory=dict)
    # 批量获取时单个资源失败不中断整体，错误记在这里而不是抛异常
    error: Optional[str] = None


def from_text(code: str, origin: str = "") -> Source:
    """从源码文本构造输入。"""
    if code is None:
        code = ""
    return Source(text=code, input_type="text", origin=origin)


def from_file(path: str) -> Source:
    """从本地文件构造输入。带编码回退，读不了就明确报错而不是静默返回空。"""
    raw = _read_bytes(path)
    truncated = False
    if MAX_SOURCE_BYTES > 0 and len(raw) > MAX_SOURCE_BYTES:
        raw = raw[:MAX_SOURCE_BYTES]
        truncated = True

    last_error: Optional[Exception] = None
    for encoding in _ENCODINGS:
        try:
            text = raw.decode(encoding)
            return Source(
                text=text,
                input_type="file",
                origin=path,
                encoding=encoding,
                truncated=truncated,
            )
        except UnicodeDecodeError as e:  # noqa: PERF203
            last_error = e
            continue
    raise UnicodeDecodeError(
        "jsatlas", raw, 0, len(raw),
        f"无法用 {_ENCODINGS} 中的任一编码解码文件: {path}（{last_error}）",
    )


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def decode_bytes(raw: bytes, preferred: Optional[str] = None) -> "tuple[str, str]":
    """按 `preferred` → BOM → 回退列表解码，返回 (文本, 实际编码)。

    remote.py 与 from_file 共用：HTTP 头 / meta charset 给出的编码不一定对，
    解不开时必须继续回退，而不是把整份资源判成"无法解析"。
    """
    candidates = []
    if preferred:
        candidates.append(preferred)
    for bom_encoding in ("utf-8-sig", "utf-16"):
        if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            candidates.append(bom_encoding)
    candidates.extend(_ENCODINGS)

    last_error: Optional[Exception] = None
    for encoding in candidates:
        try:
            return raw.decode(encoding), encoding
        except (UnicodeDecodeError, LookupError) as e:  # noqa: PERF203
            last_error = e
            continue
    raise UnicodeDecodeError(
        "jsatlas", raw, 0, len(raw),
        f"无法用 {candidates} 中的任一编码解码内容（{last_error}）",
    )
