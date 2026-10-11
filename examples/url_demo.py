"""
JSAtlas URL 输入演示 —— 在 IDE 里右键 Run 即可，不用敲命令、不用外网。

它做一件事：把一份 JS 放到本地 HTTP 服务上，然后**用 URL 喂给 JSAtlas**，
把"输入了什么 / 输出了什么"完整打印出来。

之所以不直接拿公网 URL 演示：JSAtlas 的 URL 输入是通用能力，但演示必须可复现，
本机不一定能出网。换成你自己的真实目标时，只需把 `TARGET_URL` 改成实际地址。

配置区改这两个即可：
    SERVE_FILE   托管哪个 js（相对本文件）
    TARGET_URL   留空自动用本地服务；也可直接写真实 URL（如 https://x.com/a.js）
"""

import sys
from pathlib import Path

# ------------------------------------------------------------------ 配置区
SERVE_FILE = "input.js"       # 由本地 HTTP 服务托管，再通过 URL 访问
TARGET_URL = ""               # 留空 = 用上面文件的本地 URL；填了就走真实 URL
OUTPUT_JSON = "output-url.json"   # 留空则不写文件
SHOW_SOURCE_LINES = 12        # 打印源码前几行作为"输入"展示
# ------------------------------------------------------------------------


def _bootstrap() -> None:
    root = Path(__file__).resolve().parent.parent
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _start_server(directory: Path):
    import functools
    import http.server
    import threading

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    return httpd, f"http://{host}:{port}"


def _rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    _bootstrap()

    import json

    from jsatlas.api import analyze_url, report
    from jsatlas.output.serializer import to_json
    from jsatlas.output.validator import validate

    here = Path(__file__).resolve().parent
    canned = (here / SERVE_FILE).resolve()
    if not canned.exists():
        print(f"[x] 找不到要托管的文件: {canned}")
        return 2

    httpd = None
    if TARGET_URL:
        url = TARGET_URL
        print(f"[1/4] 目标   {url}（配置区指定的真实 URL）")
    else:
        httpd, base = _start_server(here)
        url = f"{base}/{SERVE_FILE}"
        print(f"[1/4] 起服务   {base}  托管目录: {here}")

    print(f"[2/4] 发起 GET  {url}")

    try:
        result = analyze_url(url)
    except Exception as e:  # noqa: BLE001 - 演示脚本要把失败讲清楚
        print(f"[x] 获取/分析失败: {type(e).__name__}: {e}")
        return 2
    finally:
        if httpd is not None:
            httpd.shutdown()

    attrs = result.target.attributes
    print(f"       → HTTP {attrs.get('http_status')} · {attrs.get('content_type')} · "
          f"{attrs.get('fetched_bytes')} 字节 · {attrs.get('fetch_ms')} ms · "
          f"客户端 {attrs.get('http_client')}")

    data = report(result)
    print(f"[3/4] 分析完成 {len(data['apis'])} 个接口 / {len(data['secrets'])} 条密钥线索，"
          f"耗时 {result.statistics.duration_ms} ms")

    payload = to_json(data)
    ok, errors, mode = validate(json.loads(payload))
    print(f"[4/4] Schema 校验 {mode} → {'通过' if ok else '失败'}")
    for err in errors[:10]:
        print(f"       - {err}")
    for warning in result.statistics.warnings:
        print(f"       ! 告警: {warning}")

    # ---------------- 输入 / 输出 对照 ----------------
    _rule("输入")
    print(f"URL   : {url}")
    print(f"大小  : {result.target.size_bytes} 字节  "
          f"sha256: {result.target.content_sha256[:16]}…")
    print(f"源码前 {SHOW_SOURCE_LINES} 行:")
    for i, line in enumerate(canned.read_text(encoding="utf-8").splitlines()[:SHOW_SOURCE_LINES], 1):
        print(f"  {i:>3} | {line}")

    _rule("输出 ①  apis —— 可直接消费的接口清单")
    if not data["apis"]:
        print("（没有提取到接口）")
    for api in data["apis"]:
        print(f"\n  {api['method'] or '方法未确定'}  {api['path']}")
        # 没有 params 键 = 未提取到（不是"确认无参数"），别用 api["params"] 直接取
        params = api.get("params") or {}
        if params:
            print("    参数:")
            for name, value in params.items():
                shown = value if value else "（运行时才能确定）"
                print(f"      {name} = {shown}")
        else:
            print("    参数: （未提取到，需回到源码确认）")
        print(f"    来源: {api['source']}")

    _rule("输出 ②  secrets —— 按 JScanner2 方法判定出的密钥线索")
    if not data["secrets"]:
        print("（没有发现密钥线索）")
    for s in data["secrets"]:
        print(f"\n  [{s['risk_level']}] {s['type']}")
        print(f"    值     : {s['value'][:70]}")
        print(f"    下一步 : {s['test_suggestion']}")
        print(f"    来源   : {s['source']}")

    if OUTPUT_JSON:
        out = here / OUTPUT_JSON
        out.write_text(payload, encoding="utf-8")
        print(f"\n完整 JSON 已写入 {out}")
    else:
        print("\n未配置 OUTPUT_JSON，只打印摘要")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
