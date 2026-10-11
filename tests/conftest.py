"""pytest 公共配置。

用法：
    python -m pytest                # 在项目根目录执行
    python -m pytest -m "not slow"  # 跳过大样本对拍
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# 上游 JScanner2 的位置。对拍测试需要它；没配就跳过对拍，不判失败。
UPSTREAM_ROOT = Path(os.environ.get("JSCANNER2_ROOT", r"C:\Users\Cheng\Desktop\JScanner2"))
# 大样本（真实 webpack 产物）可选，默认不跑
BIG_SAMPLE = os.environ.get("JSATLAS_BIG_SAMPLE", "")


def fixture(name: str) -> Path:
    return FIXTURES / name


def read_fixture(name: str) -> str:
    return fixture(name).read_text(encoding="utf-8")


def upstream_available() -> bool:
    return (UPSTREAM_ROOT / "processor" / "js" / "context" / "context_extractor.py").exists()


def url_of(server, name: str) -> str:
    """本地测试服务的 URL。"""
    host, port = server.server_address[0], server.server_address[1]
    return f"http://{host}:{port}/{name}"


@pytest.fixture(scope="module")
def server():
    """托管 tests/fixtures 的进程内 HTTP 服务 —— 让 URL 相关测试离线可跑。"""
    import functools
    import http.server
    import threading

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(FIXTURES))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
