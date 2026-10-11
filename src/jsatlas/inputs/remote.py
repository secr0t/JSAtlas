"""远程 JavaScript 资源获取 —— 可选输入适配层。

这是 Phase 3 的第一块，但严格遵守 PROJECT_SPEC 的三条边界：

1. **可选**：核心分析完全不依赖本模块。`import jsatlas.api` 不会触发任何网络代码，
   本地文件与文本输入在无网环境照常工作。
2. **只取用户显式给出的 URL**：本模块绝不会对"分析过程中提取出来的 API / Endpoint"
   发起请求。主动发包验证是下游工具的职责。
3. **依赖可降级**：优先用 requests，缺失时回退标准库 urllib。
   因此即使不装任何 HTTP 库，URL 输入依然可用。

错误处理约定：
* 单个 URL 失败 → 抛 `FetchError`（调用方显式要求了这个 URL，拿不到就该报错，
  而不是静默返回一份空结果让人误以为"这个 JS 里什么都没有"）。
* 批量获取失败 → 不中断整体，错误记在 `Source.error` 里。
"""

from __future__ import annotations

import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from jsatlas.inputs.source import Source, decode_bytes

DEFAULT_USER_AGENT = "JSAtlas/0.1.0 (JavaScript security intelligence engine)"

# 连接 / 读取分开设：连不上要快速失败，读大 bundle 要给足时间
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 20.0

# 默认 0 = 不限字节数。远端资源同样是"多大就分析多大"，
# 需要自我保护时通过 FetchPolicy(max_bytes=...) 或 CLI --max-bytes 自己设。
DEFAULT_MAX_BYTES = 0

DEFAULT_MAX_REDIRECTS = 5

_CHUNK = 65536

# content-type 明显不是脚本时报个提示，但不阻断 —— 很多站点 MIME 配得很随意
_NON_JS_CONTENT_TYPES = (
    "text/html", "image/", "video/", "audio/", "font/",
    "application/pdf", "text/css", "application/octet-stream",
)


class FetchError(RuntimeError):
    """获取远程资源失败。"""

    def __init__(self, url: str, reason: str, *, status: Optional[int] = None):
        detail = f"HTTP {status}" if status else "无响应"
        super().__init__(f"获取 {url} 失败：{reason}（{detail}）")
        self.url = url
        self.reason = reason
        self.status = status


@dataclass
class FetchPolicy:
    """远程获取策略。所有限制都在这一处，避免散落到调用点。"""

    timeout: Tuple[float, float] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
    max_bytes: int = DEFAULT_MAX_BYTES
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = DEFAULT_USER_AGENT
    verify: bool = True
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    proxies: Optional[Dict[str, str]] = None
    # 安全测试常要扫内网，故默认放行；本模块不做 SSRF 防护，对不可信 URL 请自行评估
    allow_private_network: bool = True

    @property
    def total_timeout(self) -> float:
        return float(self.timeout[0] + self.timeout[1])


def is_url(value: str) -> bool:
    """判断一个入参是不是 HTTP(S) URL（供 CLI 自动分流用）。"""
    if not value or not isinstance(value, str):
        return False
    try:
        parts = urlparse(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def from_url(url: str, policy: Optional[FetchPolicy] = None) -> Source:
    """从远程 URL 获取一份 JavaScript 源码。

    返回 `Source.input_type == "url"`，HTTP 元信息放在 `Source.attributes`，
    随后由 `analyze_source` 并入 `target.attributes`。
    """
    policy = policy or FetchPolicy()
    _require_http_url(url, policy)

    started = time.perf_counter()
    try:
        status, headers, final_url, raw, truncated = _fetch(url, policy)
    except FetchError:
        raise
    except Exception as e:  # noqa: BLE001 - 任何底层异常都收敛成 FetchError
        raise FetchError(url, f"{type(e).__name__}: {e}") from e

    if status is not None and status >= 400:
        raise FetchError(url, "服务器返回错误状态", status=status)

    content_type = _header_get(headers, "content-type") or ""
    charset = _charset_of(content_type)
    text, encoding = decode_bytes(raw, preferred=charset)

    attributes: Dict[str, Any] = {
        "http_status": status,
        "content_type": content_type or None,
        "final_url": final_url,
        "redirected": bool(final_url and final_url != url),
        "fetched_bytes": len(raw),
        "fetch_ms": int((time.perf_counter() - started) * 1000),
        "http_client": "requests" if _has_requests() else "urllib",
    }
    if truncated:
        attributes["truncated_at_bytes"] = policy.max_bytes
    if _looks_like_non_js(content_type):
        attributes["content_type_unexpected"] = True

    return Source(
        text=text,
        input_type="url",
        origin=url,
        encoding=encoding,
        truncated=truncated,
        attributes=attributes,
    )


def from_urls(
    urls: Iterable[str],
    policy: Optional[FetchPolicy] = None,
    max_workers: int = 4,
) -> List[Source]:
    """并发获取多个 URL。单个失败不中断整体，错误记在 `Source.error`。"""
    url_list = [u for u in urls]
    if not url_list:
        return []
    policy = policy or FetchPolicy()
    workers = max(1, min(int(max_workers), len(url_list)))

    def _one(url: str) -> Source:
        try:
            return from_url(url, policy)
        except FetchError as e:
            return Source(text="", input_type="url", origin=url, error=str(e))
        except Exception as e:  # noqa: BLE001
            return Source(text="", input_type="url", origin=url,
                          error=f"{type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_one, url_list))


# --------------------------------------------------------------------------
# 内部实现
# --------------------------------------------------------------------------

def _require_http_url(url: str, policy: FetchPolicy) -> None:
    try:
        parts = urlparse(url)
    except ValueError as e:
        raise FetchError(url, f"URL 无法解析：{e}") from e
    if parts.scheme not in ("http", "https"):
        raise FetchError(
            url,
            f"只支持 http / https，拒绝 scheme={parts.scheme or '(空)'}",
        )
    if not parts.netloc:
        raise FetchError(url, "URL 缺少主机名")


def _has_requests() -> bool:
    try:
        import requests  # noqa: F401
    except ImportError:
        return False
    return True


def _fetch(url: str, policy: FetchPolicy):
    """分派到具体 HTTP 客户端，统一返回 (status, headers, final_url, raw, truncated)。"""
    if _has_requests():
        return _fetch_with_requests(url, policy)
    return _fetch_with_urllib(url, policy)


def _fetch_with_requests(url: str, policy: FetchPolicy):
    import requests

    headers = {"User-Agent": policy.user_agent, "Accept": "*/*"}
    headers.update(policy.headers or {})

    with requests.Session() as session:
        session.max_redirects = policy.max_redirects
        if policy.proxies:
            session.proxies.update(policy.proxies)
        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=policy.timeout,
                verify=policy.verify,
                allow_redirects=True,
                stream=True,
            )
        except requests.RequestException as e:
            raise FetchError(url, f"{type(e).__name__}: {e}") from e

        try:
            raw, truncated = _read_limited(
                resp.iter_content(chunk_size=_CHUNK), policy.max_bytes)
            return resp.status_code, dict(resp.headers), resp.url, raw, truncated
        finally:
            resp.close()


def _fetch_with_urllib(url: str, policy: FetchPolicy):
    import urllib.error
    import urllib.request

    headers = {"User-Agent": policy.user_agent, "Accept": "*/*"}
    headers.update(policy.headers or {})

    context = None
    if not policy.verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        _build_urllib_redirect_handler(policy.max_redirects))
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=policy.total_timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            raw, truncated = _read_limited(
                iter(lambda: resp.read(_CHUNK), b""), policy.max_bytes)
            return status, dict(resp.headers.items()), resp.geturl(), raw, truncated
    except urllib.error.HTTPError as e:
        # HTTPError 本身是响应对象，状态码要能带出去
        try:
            return e.code, dict(e.headers.items() or {}), url, b"", False
        except Exception:  # noqa: BLE001
            raise FetchError(url, f"HTTPError {e.code}", status=e.code) from e
    except urllib.error.URLError as e:
        raise FetchError(url, f"URLError: {e.reason}") from e
    except TimeoutError as e:
        raise FetchError(url, f"超时（{policy.total_timeout}s）: {e}") from e


def _build_urllib_redirect_handler(max_redirects: int):
    """urllib 不暴露重定向次数上限，这里自己数。"""
    import urllib.request

    class _Handler(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self._max = max_redirects
            self._count = 0

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self._count += 1
            if self._count > self._max:
                raise RuntimeError(f"重定向次数超过上限 {self._max}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return _Handler()


def _read_limited(chunks: Iterable[bytes], max_bytes: int) -> "Tuple[bytes, bool]":
    """流式读取并在超过上限时截断 —— 不看 Content-Length，那个经常撒谎。

    max_bytes <= 0 表示不限（默认）。
    """
    buf = bytearray()
    truncated = False
    limit = max_bytes if max_bytes and max_bytes > 0 else None
    for chunk in chunks:
        if not chunk:
            continue
        buf.extend(chunk)
        if limit is not None and len(buf) >= limit:
            del buf[limit:]
            truncated = True
            break
    return bytes(buf), truncated


def _header_get(headers: Dict[str, Any], name: str) -> Optional[str]:
    if not headers:
        return None
    lowered = {str(k).lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def _charset_of(content_type: str) -> Optional[str]:
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1].strip().strip('"\'') or None
    return None


def _looks_like_non_js(content_type: str) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return any(lowered.startswith(x) for x in _NON_JS_CONTENT_TYPES)
