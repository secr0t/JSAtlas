"""锁定决策：JSAtlas 不对源码设字符上限，也不默认限制上下文恢复数量。

这三条曾经真实存在，用户在大 bundle 上看到了"已跳过 xxx"的告警，等于把最大的
那批目标整体放弃。本文件把它们钉住，防止以后有人以"防 DoS / 防超时"为名加回来。

真正需要自我保护时走显式参数：`FetchPolicy(max_bytes=...)`、`--max-bytes`、
`AnalysisOptions.max_context_targets=N`、`--max-context-targets N`。默认一律不限。
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from jsatlas.analyzers.intelligence import upstream_secret
from jsatlas.analyzers.intelligence.secret_scoring import AdvancedSecretFilter, CodeLineFilter
from jsatlas.analyzers.parameters import upstream_param_pipeline
from jsatlas.inputs import remote, source
from jsatlas.pipeline.context import AnalysisOptions

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "jsatlas"

# 曾经带着源码字符上限的模块
# （正则链路 upstream_regex / secret_regex 已按项目决策移除，不再受此约束）
_GUARDED_MODULES = [
    upstream_secret,
    upstream_param_pipeline,
]


def _scoring_hits(text: str) -> set:
    """跑一遍确定性的行切片 + 熵/分词打分，返回命中值集合。

    不经过 format_code / AST / LLM —— 纯计算，百万字符也能在秒级跑完。
    """
    line_filter = CodeLineFilter()
    adv = AdvancedSecretFilter(threshold=0.75)
    return {content for content, _line in line_filter.extract_candidates(text)
            if adv.is_secret(content)}


def _module_text(mod) -> str:
    return inspect.getsource(mod)


def _module_ast(mod):
    return ast.parse(_module_text(mod))


def _assignment_names(tree) -> set:
    """模块级赋值的变量名（只看代码，注释里提到不算）。"""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _compare_constants(tree):
    """所有 `left op right` 里的数字常量，用来抓长度阈值。"""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for side in (node.left, *node.comparators):
                if isinstance(side, ast.Constant) and isinstance(side.value, int):
                    out.append(side.value)
    return out


# ---------------- 1. 源码字符上限：必须彻底消失 ----------------

@pytest.mark.parametrize("mod", _GUARDED_MODULES,
                         ids=[m.__name__.rsplit(".", 1)[-1] for m in _GUARDED_MODULES])
def test_no_source_char_limit_constant(mod):
    """不许再定义 _MAX_TEXT_CHARS 之类的源码长度上限（注释里提到可以）。"""
    names = _assignment_names(_module_ast(mod))
    offenders = {n for n in names if "MAX" in n and "CHAR" in n.upper()}
    assert not offenders, f"{mod.__name__} 仍有源码字符上限常量：{offenders}"


@pytest.mark.parametrize("mod", _GUARDED_MODULES,
                         ids=[m.__name__.rsplit(".", 1)[-1] for m in _GUARDED_MODULES])
def test_no_length_guard_in_source(mod):
    """不许再出现"源码超过 N 字符就跳过"的保护。

    只抓量级在 10 万以上的阈值 —— `len(text) > 500` 这种是取尾部切片，不是跳过。
    """
    tree = _module_ast(mod)
    thresholds = [n for n in _compare_constants(tree) if n >= 100_000]
    assert not thresholds, f"{mod.__name__} 里仍有大长度阈值：{thresholds}"


def test_scoring_still_runs_on_megabyte_source():
    """百万字符以上的源码，计算式打分必须照跑（上游那条 1000000 保护已移除）。"""
    body = "var a0 = 1;\n" * 84_000              # 12 × 84,000 = 1,008,000 字符
    assert len(body) > 1_000_000, len(body)
    text = body + 'var k = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";'

    assert "9f8e7d6c5b4a39281706f5e4d3c2b1a0" in _scoring_hits(text)


def test_secret_found_at_the_very_end_of_large_source():
    """线索放在源码末尾也必须能扫到 —— 截断/跳过的典型受害位置。"""
    body = "var x = 1;\n" * 91_000                # 11 × 91,000 = 1,001,000 字符
    text = body + 'var k = "aB3dEf7hJk2mNp5qRs8tUv1w";'
    assert len(text) > 1_000_000
    assert "aB3dEf7hJk2mNp5qRs8tUv1w" in _scoring_hits(text)


# ---------------- 2. 输入层：默认不截断 ----------------

def test_no_default_byte_cap():
    assert source.MAX_SOURCE_BYTES == 0, "本地文件又设了默认字节上限"
    assert remote.DEFAULT_MAX_BYTES == 0, "远程资源又设了默认字节上限"
    assert remote.FetchPolicy().max_bytes == 0


def test_large_text_input_is_not_truncated():
    big = "a" * 5_000_000
    src = source.from_text(big, origin="big.js")
    assert src.truncated is False
    assert len(src.text) == 5_000_000


def test_explicit_max_bytes_still_works():
    """默认不限 ≠ 不能限：显式传值时截断行为要保留。"""
    raw, truncated = remote._read_limited([b"0123456789"], max_bytes=4)
    assert truncated is True
    assert raw == b"0123"


# ---------------- 3. 上下文恢复：默认不限数量 ----------------

def test_context_targets_unlimited_by_default():
    assert AnalysisOptions().max_context_targets == 0


def test_many_surfaces_do_not_trigger_context_limit_warning():
    """几百个攻击面时，不应该再出现"超过上下文恢复上限"的告警。"""
    from jsatlas.api import analyze_source
    from jsatlas.inputs.source import from_text

    lines = ['fetch("/api/v%d/list", {method: "POST"});' % i for i in range(300)]
    result = analyze_source(from_text("\n".join(lines), origin="many.js"))

    offenders = [w for w in result.statistics.warnings if "上下文恢复上限" in w]
    assert not offenders, offenders
    assert len(result.surfaces) >= 300


# ---------------- 4. 攻击面候选：默认不限条数 ----------------

def test_surface_candidate_cap_removed():
    """攻击面上限原来是 5000，命中后直接 return —— 整棵 AST 的遍历就此中止。

    现在是 0 = 不限。这里造 6000 条不同路径，确认全部提出且无告警。
    """
    from jsatlas.analyzers.surfaces import path_candidates

    assert path_candidates._MAX_SURFACES == 0, "攻击面候选上限又被加回来了"

    from jsatlas.api import analyze_source
    from jsatlas.inputs.source import from_text
    from jsatlas.pipeline.context import AnalysisOptions

    text = "\n".join('fetch("/api/resource/%d");' % i for i in range(6000))
    options = AnalysisOptions(analyzers=["surface.path_candidates"])
    result = analyze_source(from_text(text, origin="many.js"), options=options)

    assert not result.statistics.warnings, result.statistics.warnings
    assert len(result.surfaces) >= 6000, len(result.surfaces)


# ---------------- 5. 端到端：大源码不该出现任何"跳过"告警 ----------------

def test_secret_scoring_runs_on_megabyte_source():
    """百万字符以上的源码，计算式打分链路不能"已跳过"。

    这里直接调确定性打分函数而不是走完整流水线：密钥链路会先 `format_code`
    格式化，几 MB 的 bundle 要跑分钟级，塞进单元测试不合适。
    要锁的是"没有字符上限/不截断"，打分函数就是那道关。
    """
    body = "var a0 = 1;\n" * 84_000               # > 1,000,000 字符
    assert len(body) > 1_000_000, len(body)
    text = body + 'var k = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";'

    assert "9f8e7d6c5b4a39281706f5e4d3c2b1a0" in _scoring_hits(text)
