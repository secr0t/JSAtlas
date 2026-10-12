"""JSAtlas MCP server（stdio transport，零依赖）。

面向其他 Agent 的标准接入点：任何支持 MCP 协议的客户端（Claude Code、
Cline、自定义红队 agent 等）都能通过 tools/list / tools/call 调用 JSAtlas，
不用拼命令行、不用解析 stdout/stderr。

实现说明：
* 纯 stdio + JSON-RPC 2.0，newline-delimited —— 不引入 mcp SDK，零运行时依赖；
* 只实现本服务需要的四个方法：initialize / tools/list / tools/call / ping，
  其余方法（resources / prompts / notifications）安全忽略；
* 日志一律走 stderr，stdout 只承载协议帧，避免污染 JSON-RPC 流。

启动：
    python -m jsatlas.mcp_server
    jsatlas-mcp                    # pip install 后的等价入口

客户端配置示例（Claude Code）：
    "mcpServers": {
      "jsatlas": { "command": "jsatlas-mcp" }
    }
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from jsatlas.api import (
    AnalysisOptions,
    analyze_file,
    analyze_url,
    available_analyzers,
    report,
    validate,
)
from jsatlas.pipeline.registry import all_analyzers

# MCP 协议版本：取最广泛兼容的 2024-11-05
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "jsatlas-mcp", "version": "0.1.0"}

# mode → 分析器维度。None 表示跑全部（与 CLI --mode 语义一致）
_MODE_DIMENSIONS: Dict[str, Optional[tuple]] = {
    "all": None,
    "api": ("surface", "parameters", "context"),
    "secret": ("intelligence",),
}

_ANALYZE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {
            "type": "string",
            "description": "JavaScript 源码的本地文件路径或远程 URL",
        },
        "mode": {
            "type": "string",
            "enum": ["all", "api", "secret"],
            "default": "all",
            "description": "all=API+密钥全跑；api=只跑 API 链路；secret=只跑密钥链路",
        },
        "validate": {
            "type": "boolean",
            "default": False,
            "description": "输出前做 Schema 校验，结果附在返回文本里",
        },
    },
    "required": ["source"],
}

_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "analyze_js",
        "description": (
            "分析一段 JavaScript（本地文件或 URL），提取 API 攻击面（路径/方法/参数）"
            "与可疑密钥，返回 {\"apis\": [...], \"secrets\": [...]}。"
        ),
        "inputSchema": _ANALYZE_SCHEMA,
    },
    {
        "name": "list_analyzers",
        "description": "列出已注册的分析器（name/dimension/description），用于挑选 --analyzers。",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------- 工具实现
def _analyzers_for_mode(mode: str) -> Optional[List[str]]:
    dimensions = _MODE_DIMENSIONS.get(mode, _MODE_DIMENSIONS["all"])
    if dimensions is None:
        return None
    return [a.name for a in all_analyzers() if a.dimension in dimensions]


def _analyze_js(args: Dict[str, Any]) -> Dict[str, Any]:
    source = str(args.get("source", "")).strip()
    if not source:
        return _tool_error("source 不能为空")
    mode = args.get("mode", "all")
    if mode not in _MODE_DIMENSIONS:
        return _tool_error(f"mode 必须是 all/api/secret，收到: {mode!r}")

    options = AnalysisOptions(analyzers=_analyzers_for_mode(mode))

    try:
        if source.startswith(("http://", "https://")):
            result = analyze_url(source, options=options)
        else:
            result = analyze_file(source, options=options)
    except Exception as exc:  # FetchError / FileNotFoundError 等，把根因透传给客户端
        return _tool_error(f"分析失败: {type(exc).__name__}: {exc}")

    data = report(result)

    if args.get("validate"):
        ok, errors, mode_name = validate(data)
        data["_validation"] = {"ok": ok, "errors": errors, "mode": mode_name}

    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}],
        "isError": False,
    }


def _list_analyzers(_args: Dict[str, Any]) -> Dict[str, Any]:
    text = json.dumps(available_analyzers(), ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _tool_error(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


_TOOL_IMPL = {
    "analyze_js": _analyze_js,
    "list_analyzers": _list_analyzers,
}


# ---------------------------------------------------------------- 协议层
def _rpc_error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        impl = _TOOL_IMPL.get(name)
        if impl is None:
            return _rpc_error(req_id, -32602, f"未知工具: {name!r}")
        result = impl(params.get("arguments") or {})
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    # notifications/initialized、notifications/cancelled、resources/* 等：安全忽略
    if req_id is None:
        return None
    return _rpc_error(req_id, -32601, f"不支持的 method: {method!r}")


def run() -> int:
    """主循环：逐行读 stdin，处理 JSON-RPC 帧，响应写 stdout。"""
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"[jsatlas-mcp] 丢弃无法解析的帧: {exc}\n")
            sys.stderr.flush()
            continue
        try:
            response = _handle(msg)
        except Exception as exc:  # 协议层兜底：绝不因单帧异常退出
            sys.stderr.write(f"[jsatlas-mcp] 处理帧异常: {type(exc).__name__}: {exc}\n")
            sys.stderr.flush()
            if "id" in msg and msg["id"] is not None:
                response = _rpc_error(msg["id"], -32603, str(exc))
            else:
                response = None
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
