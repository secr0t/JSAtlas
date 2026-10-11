"""两条明确的工程决策：AI 默认开启、去重只用单次运行内的朴素集合。

这两条都是用户明确拍过的板，写成测试是为了防止后面有人"顺手"改回去：
* 又加回 `--enable-ai` 开关 —— 工具默认就需要 AI；
* 又换成布隆过滤器或落盘复用 —— 单次量级用不上，且假阳性会把漏报变成概率问题。
"""

from __future__ import annotations

import pytest

from tests.conftest import PROJECT_ROOT, read_fixture


def test_enable_ai_defaults_to_true():
    """AI 是默认能力，不是可选开关。"""
    from jsatlas.pipeline.context import AnalysisOptions

    assert AnalysisOptions().enable_ai is True


def test_cli_has_no_enable_ai_flag():
    """`--enable-ai` 已移除：传它应当被 argparse 拒绝，而不是被静默忽略。"""
    from jsatlas.cli import _build_parser

    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--enable-ai", "app.js"])

    # 正常路径不受影响
    args = parser.parse_args(["app.js"])
    assert args.target == ["app.js"]


def test_dedup_is_exact_set_without_false_positive():
    """朴素集合不存在假阳性：没加过的元素一律 contains=False。

    这是相对布隆过滤器的关键差异 —— Bloom 在同样规模下会有约 0.1% 的误判，
    而误判在这里等于"明明没见过的候选被当成见过而丢掉"。
    """
    from jsatlas.utils.dedup import MemoryDedup

    dedup = MemoryDedup("probe", capacity=500000, error_rate=0.001)
    present = {f"seen-{i}" for i in range(20000)}
    absent = {f"unseen-{i}" for i in range(20000)}
    for value in present:
        dedup.add(value)

    assert all(dedup.contains(v) for v in present)
    assert not any(dedup.contains(v) for v in absent), "出现了假阳性，说明不是精确集合"
    assert len(dedup) == len(present)


def test_scan_resets_dedup_each_run():
    """每次 scan 都换成全新的去重集合 —— 单次运行内去重，跨调用不抑制。"""
    from jsatlas.analyzers.intelligence import upstream_secret_scanner as mod

    before = mod._OUTPUT_LINE_DEDUP
    SensitiveInfoScanner = mod.SensitiveInfoScanner
    scanner = SensitiveInfoScanner()

    scanner.scan(read_fixture("secret.js"), "secret.js")
    after = mod._OUTPUT_LINE_DEDUP

    assert after is not before, "scan 没有重置去重集合，跨调用会互相抑制"
    # 重置后是一张干净的表：上一轮见过的行这一轮重新参与判定
    scanner.scan(read_fixture("secret.js"), "secret.js")
    assert mod._OUTPUT_LINE_DEDUP is not after


def test_no_bloom_artifacts_left_behind():
    """跑完一次分析，工程目录里不能出现任何 .bloom / Result 落盘产物。"""
    from jsatlas.api import analyze_source
    from jsatlas.inputs.source import from_text

    analyze_source(from_text(read_fixture("secret.js"), origin="secret.js"))

    artifacts = [p for p in PROJECT_ROOT.rglob("*.bloom")]
    assert not artifacts, f"出现了布隆过滤器落盘文件：{artifacts}"
    assert not (PROJECT_ROOT / "Result").exists(), "不应创建 Result 目录"


def test_ai_stage_runs_by_default_without_key():
    """没配 Key 时是降级而不是跳过：链路照跑，结论带 ai_verified=False。"""
    from jsatlas.api import analyze_source
    from jsatlas.inputs.source import from_text

    result = analyze_source(from_text(read_fixture("secret.js"), origin="secret.js"))
    stats = result.statistics.analyzers

    # 分析器必须真的执行过，不能因为没 Key 就被整体跳过
    # （密钥链路会额外给出候选/复核数，所以这里取 status 比对）
    entry = stats.get("intelligence.upstream_secret")
    status = entry.get("status") if isinstance(entry, dict) else entry
    assert status == "ok", stats
