"""
JSAtlas 演示入口 —— 在 IDE 里右键 Run 即可，不用敲命令、不用传参数。

改动上面 `配置区` 里的两个变量就能换目标：
    TARGET_JS   要分析的 js 文件（也可以是 http(s):// 开头的 JS URL）
    OUTPUT_JSON 结果写到哪里（留空则打印到控制台）

正式使用请用命令行：
    python -m jsatlas <file.js> -o result.json --validate
"""

import sys
from pathlib import Path

# ------------------------------------------------------------------ 配置区
TARGET_JS = "https://cdn1.xdf.cn/cms-ssr-app-node/1-10120e83.js"
OUTPUT_JSON = "result.json"          # 例如 "result.json"；留空则只打印
ANALYZERS = None          # 例如 ["surface.path_candidates"]；None 表示跑全部
# ----------------------------------------------------------------------


def _bootstrap() -> None:
    """让脚本在任意 CWD 下都能找到 src/jsatlas。"""
    root = Path(__file__).resolve().parent
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> int:
    _bootstrap()

    import json

    from jsatlas.output.serializer import to_json
    from jsatlas.output.validator import validate
    from jsatlas.pipeline.context import AnalysisOptions

    raw_target = TARGET_JS
    is_url = raw_target.startswith(("http://", "https://"))

    print(f"[1/4] 输入   {raw_target}{'（远程抓取）' if is_url else ''}")
    options = AnalysisOptions(analyzers=ANALYZERS)
    print(f"[2/4] 分析   分析器={'全部' if ANALYZERS is None else ANALYZERS}")

    from jsatlas.api import analyze_file, analyze_url, report

    if is_url:
        result = analyze_url(raw_target, options=options)
    else:
        target = (Path(__file__).resolve().parent / raw_target).resolve()
        if not target.exists():
            print(f"[x] 找不到文件: {target}")
            print("    改一下本文件顶部配置区里的 TARGET_JS")
            return 2
        result = analyze_file(str(target), options=options)

    data = report(result)
    print(f"[3/4] 完成   {len(data['apis'])} 个接口 / "
          f"{len(data['secrets'])} 条密钥线索，"
          f"耗时 {result.statistics.duration_ms} ms")

    # 密钥链路明细：secrets 为空时，得让人看出是"没有候选"还是"候选被 AI 否掉了"
    secret_stats = result.statistics.analyzers.get("intelligence.upstream_secret")
    if isinstance(secret_stats, dict):
        print(f"       密钥链路：候选 {secret_stats['candidates']} 条 → "
              f"保留 {secret_stats['kept']} 条"
              f"（AI 复核 {'已执行' if secret_stats['ai_used'] else '未启用'}）")

    payload = to_json(data)
    ok, errors, mode = validate(json.loads(payload))
    print(f"[4/4] 校验   {mode} → {'通过' if ok else '失败'}")
    for err in errors[:10]:
        print(f"       - {err}")

    for warning in result.statistics.warnings:
        print(f"       ! 告警: {warning}")

    if OUTPUT_JSON:
        out = Path(OUTPUT_JSON)
        if not out.is_absolute():
            out = Path(__file__).resolve().parent / out
        out.write_text(payload, encoding="utf-8")
        print(f"[+] 已写入 {out}")
        return 0 if ok else 1

    print("\n" + payload)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
