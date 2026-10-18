"""JSAtlas 命令行入口。

    python -m jsatlas app.js                      # 本地文件
    python -m jsatlas https://x.com/a.js          # 远程 URL
    python -m jsatlas https://a/x.js https://b/y.js -o report.json
    python -m jsatlas app.js -o out.json --validate
    python -m jsatlas https://x.com/a.js --header "Cookie: session=xxx"
    python -m jsatlas app.js --mode api           # 只跑 API 链路
    python -m jsatlas app.js --mode secret        # 只跑密钥链路

无论是单个还是多个目标，输出形态都一样：

```json
{"api_with_param": [{"path": "/security/api/v1/...", "method": "POST", "params": {...},
                     "reconstruct": {"envelope_rewrite": {...}, "api_is_exempt": false},
                     "source": "..."}],
 "api_without_param": [{"path": "...", "method": "GET", "source": "..."}],
 "secrets": [{"value": "...", "type": "...", "risk_level": "High",
              "test_suggestion": "...", "source": "..."}]}
```

多个资源的结果合并进同一份清单，每条自带 `source`，不会混淆出处。

`--mode` 是给自动化调用方（Agent / 脚本）准备的任务级开关：
只跑 API、只跑密钥、或全跑。无论哪种模式，输出形态都不变 ——
永远是 `{"api_with_param": [...], "api_without_param": [...], "secrets": [...]}` 三键，
不相关的一侧为空列表，调用方不需要按模式改解析逻辑。

`params` 只在真的提取到参数时出现；缺失表示"未提取到参数"，
**不代表该接口确认无参数**（详见 README「`params` 缺失意味着什么」）。
有 params 的接口进 `api_with_param`，没有的进 `api_without_param`。
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

import jsatlas.analyzers  # noqa: F401 - 触发分析器注册
from jsatlas import __version__
from jsatlas.api import analyze_source, available_analyzers
from jsatlas.inputs.remote import FetchPolicy, from_url, from_urls, is_url
from jsatlas.inputs.source import Source, from_file, from_text
from jsatlas.output.report import build_report, merge_reports
from jsatlas.output.serializer import to_json
from jsatlas.output.validator import validate
from jsatlas.llm import llm_available
from jsatlas.pipeline.context import AnalysisOptions
from jsatlas.pipeline.registry import all_analyzers
from jsatlas.utils.logging import configure_logging


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsatlas",
        description="JSAtlas — JavaScript 安全情报提取引擎",
    )
    parser.add_argument("target", nargs="*",
                        help="待分析的 .js 文件路径或 JS 的 URL；`-` 表示从 stdin 读取")
    parser.add_argument("-o", "--out", help="输出 JSON 文件路径；不指定则输出到 stdout")
    parser.add_argument("--indent", type=int, default=2, help="JSON 缩进，0 表示压缩输出")
    parser.add_argument("--analyzers", nargs="*", default=None,
                        help="只运行指定的分析器（按 name）；显式指定时优先于 --mode")
    parser.add_argument("--mode", choices=("all", "api", "secret"), default="all",
                        help="任务级运行模式：all=API+密钥全跑（默认）；"
                             "api=只跑 API 链路；secret=只跑密钥链路。"
                             "输出形态不变，不相关一侧为空列表")
    parser.add_argument("--list-analyzers", action="store_true", help="列出已注册的分析器并退出")
    parser.add_argument("--validate", action="store_true",
                        help="输出前做结构 / JSON Schema 校验，失败则退出码非 0")
    parser.add_argument("--proximity-link", type=int, default=0,
                        help="按行号邻近把情报关联到攻击面（默认 0，关闭）")
    parser.add_argument("--max-context-targets", type=int, default=0,
                        help="上下文恢复最多处理多少个 API（默认 0 = 不限）")

    fetch = parser.add_argument_group("远程获取（仅 URL 目标生效）")
    fetch.add_argument("--timeout", type=float, default=None,
                       help="读取超时秒数（默认 20；连接超时固定 5 秒）")
    fetch.add_argument("--max-bytes", type=int, default=None,
                       help="单个远程资源的字节上限（默认不限）")
    fetch.add_argument("--header", action="append", default=[], metavar="K: V",
                       help="附加请求头，可重复；用于带 Cookie 抓取需鉴权的 JS")
    fetch.add_argument("--insecure", action="store_true",
                       help="关闭 TLS 证书校验（自签名环境用，默认校验）")
    fetch.add_argument("--workers", type=int, default=4,
                       help="多个 URL 时的并发获取数（默认 4）")

    parser.add_argument("-v", "--verbose", action="store_true", help="输出日志")
    parser.add_argument("--version", action="version", version=f"jsatlas {__version__}")
    return parser


# 任务级模式 → 分析器维度。all 不在表里 = 跑全部已注册的。
# secret 链路（intelligence.upstream_secret）自带行切片，不依赖 surface，
# 所以"只跑密钥"时跳过 API 链路是安全的，还能省掉整条 AST 上下文恢复的开销。
_MODE_DIMENSIONS = {
    "api": ("surface", "parameters", "context"),
    "secret": ("intelligence",),
}


def _analyzers_for_mode(mode: str) -> Optional[List[str]]:
    """把运行模式翻译成分析器名单；all 返回 None（跑全部）。

    名单按注册顺序生成（parameters → context → surfaces → intelligence），
    与全量运行的执行顺序一致，模式切换不改变分析器之间的先后依赖。
    """
    dimensions = _MODE_DIMENSIONS.get(mode)
    if dimensions is None:
        return None
    return [a.name for a in all_analyzers() if a.dimension in dimensions]


def _build_policy(args: argparse.Namespace) -> FetchPolicy:
    policy = FetchPolicy()
    if args.timeout is not None:
        policy.timeout = (policy.timeout[0], args.timeout)
    if args.max_bytes is not None:
        policy.max_bytes = args.max_bytes
    policy.verify = not args.insecure
    for raw in args.header or []:
        if ":" not in raw:
            print(f"警告：忽略格式不正确的请求头 {raw!r}（应为 'Name: value'）",
                  file=sys.stderr)
            continue
        name, _, value = raw.partition(":")
        policy.headers[name.strip()] = value.strip()
    return policy


def _collect_sources(args: argparse.Namespace) -> List[Source]:
    """按顺序把每个目标变成 Source。

    单个 URL 走 `from_url`：拿不到就抛错退出（用户显式要这一个，失败必须响亮）。
    多个目标走 `from_urls`：个别失败不连累整体，错误记在结果里。
    """
    targets = list(args.target or [])
    policy = _build_policy(args)

    if len(targets) == 1 and is_url(targets[0]):
        return [from_url(targets[0], policy)]

    url_targets = [t for t in targets if is_url(t)]
    fetched: Dict[str, Source] = {}
    if url_targets:
        if args.verbose:
            print(f"[fetch] 并发获取 {len(url_targets)} 个 URL（workers={args.workers}）",
                  file=sys.stderr)
        for src in from_urls(url_targets, policy=policy, max_workers=args.workers):
            fetched[src.origin] = src

    sources: List[Source] = []
    for target in targets:
        if target == "-":
            sources.append(from_text(sys.stdin.read(), origin="<stdin>"))
        elif is_url(target):
            sources.append(fetched[target])
        else:
            sources.append(from_file(target))
    return sources


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.verbose:
        configure_logging()

    if args.list_analyzers:
        print(json.dumps(available_analyzers(), ensure_ascii=False, indent=2))
        return 0

    if not args.target:
        print("错误：请提供待分析的 .js 文件路径、JS 的 URL（或用 `-` 从 stdin 读取）",
              file=sys.stderr)
        return 2

    # --analyzers 是更精确的指定，优先于 --mode 的粗粒度分组
    analyzers = args.analyzers
    if analyzers is None:
        analyzers = _analyzers_for_mode(args.mode)

    options = AnalysisOptions(
        analyzers=analyzers,
        proximity_link_lines=args.proximity_link,
        max_context_targets=args.max_context_targets,
        enable_ai=True,
    )

    if not llm_available():
        print(
            "警告：未检测到可用的大模型配置，AI 阶段（密钥 LLM 复核 / 参数 Level 2-3）"
            "将降级为确定性结果，\n"
            "      输出里的 type / risk_level / test_suggestion 会是兜底标签而非模型判定。\n"
            "      设置环境变量 JSATLAS_LLM_API_KEY（可选 JSATLAS_LLM_BASE_URL、JSATLAS_LLM_MODELS）后重试。",
            file=sys.stderr)

    try:
        sources = _collect_sources(args)
    except Exception as e:  # noqa: BLE001 - CLI 要把任何获取失败收敛成一条可读错误
        print(f"错误：{type(e).__name__}: {e}", file=sys.stderr)
        return 2

    results = [analyze_source(s, options=options) for s in sources]

    data = (build_report(results[0]) if len(results) == 1 else merge_reports(results))
    payload = to_json(data, indent=args.indent)
    summary = _summary(data)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"[+] 已写入 {args.out}（{summary}）")
    else:
        print(payload)

    # 批量模式下个别资源失败不中断，但必须体现在退出码上，否则脚本无从判断
    failed = False
    for r in results:
        origin = r.target.origin if r.target else ""
        for err in r.statistics.errors:
            print(f"错误：{origin}: {err}", file=sys.stderr)
            failed = True

    if args.validate:
        ok, errors, mode = validate(data)
        print(f"[validate] 方式={mode} 结果={'通过' if ok else '失败'}", file=sys.stderr)
        for err in errors[:20]:
            print(f"  - {err}", file=sys.stderr)
        if not ok:
            return 1

    return 1 if failed else 0


def _summary(data: Dict[str, Any]) -> str:
    n_api = len(data.get("api_with_param", [])) + len(data.get("api_without_param", []))
    return f"apis={n_api}, secrets={len(data.get('secrets', []))}"


if __name__ == "__main__":
    raise SystemExit(main())
