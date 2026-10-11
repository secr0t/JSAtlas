"""AI 接入配置：**配置文件为主，环境变量覆盖**。

上游从 `config/config.py` 读硬编码常量，密钥等于写死在代码里。JSAtlas 改成读配置文件，
这样密钥不进仓库、也不必每次开终端都 export。

查找顺序（先命中先赢，逐文件整体生效）：

1. `JSATLAS_CONFIG` 环境变量指向的文件（显式指定时用这个）
2. 当前目录的 `jsatlas.config.json`（按项目放一份，最省事）
3. `~/.jsatlas/config.json`（用户级，放一次到处生效）
4. 项目根的 `config/llm.json`（随仓库带的默认位）

**环境变量优先级最高**，用于临时切换而不改文件：

    JSATLAS_LLM_API_KEY     模型网关的 API Key
    JSATLAS_LLM_BASE_URL    默认 https://dashscope.aliyuncs.com/compatible-mode/v1
    JSATLAS_LLM_MODELS      逗号分隔的模型名列表，留空则走 models_config.json
    JSATLAS_LLM_CONFIG      模型配置文件路径（可选，热更新用）
    JSATLAS_LLM_TIMEOUT     单次请求超时秒数，默认 30

配置文件示例见 `config/llm.example.json`。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

# src/jsatlas/llm/settings.py -> llm(0) / jsatlas(1) / src(2) / 项目根(3)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_CWD_CONFIG = "jsatlas.config.json"
_USER_CONFIG = Path.home() / ".jsatlas" / "config.json"
_PROJECT_CONFIG = _PROJECT_ROOT / "config" / "llm.json"

_DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
_DEFAULT_TIMEOUT = 30

# 配置文件里允许的各种写法统一收敛到规范键上
_ALIASES = {
    "api_key": "api_key", "apikey": "api_key", "key": "api_key",
    "base_url": "base_url", "baseurl": "base_url", "endpoint": "base_url",
    "models": "models", "model": "models",
    "config_path": "config_path", "model_config_path": "config_path",
    "timeout": "timeout",
}

# 加载配置文件过程中的问题（文件存在但 JSON 坏了之类）。
# 不在 import 阶段直接 print —— 那是副作用；交给 CLI 在启动时统一打印。
CONFIG_ERRORS: List[str] = []


def _candidate_paths() -> List[Path]:
    paths: List[Path] = []
    env_path = os.environ.get("JSATLAS_CONFIG", "").strip()
    if env_path:
        paths.append(Path(env_path).expanduser())
    paths.append(Path.cwd() / _CWD_CONFIG)
    paths.append(_USER_CONFIG.expanduser())
    paths.append(_PROJECT_CONFIG)
    return paths


def _normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """把用户可能写的各种键名收敛成规范键；支持顶层再包一层 `llm`。"""
    data: Dict[str, Any] = {}
    section = raw.get("llm")
    if isinstance(section, dict):
        data.update(section)
    data.update(raw)

    out: Dict[str, Any] = {}
    for key, value in data.items():
        canon = _ALIASES.get(str(key).strip().lower())
        if canon and value not in (None, ""):
            out[canon] = value
    return out


def _load_config_file() -> Tuple[Dict[str, Any], str]:
    for path in _candidate_paths():
        try:
            if not path.is_file():
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            CONFIG_ERRORS.append(f"配置文件无法读取 {path}：{exc}")
            continue
        except ValueError as exc:
            CONFIG_ERRORS.append(f"配置文件不是合法 JSON {path}：{exc}")
            continue

        if not isinstance(raw, dict):
            CONFIG_ERRORS.append(f"配置文件顶层应为对象 {path}，实际 {type(raw).__name__}")
            continue
        return _normalize(raw), str(path)
    return {}, ""


def _as_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [m.strip() for m in value.split(",") if m.strip()]
    if isinstance(value, (list, tuple)):
        return [str(m).strip() for m in value if str(m).strip()]
    return []


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_FILE, CONFIG_SOURCE = _load_config_file()

# 环境变量 > 配置文件 > 内置默认值
BASE_URL = os.environ.get("JSATLAS_LLM_BASE_URL", "").strip() or str(
    _FILE.get("base_url") or _DEFAULT_BASE_URL)
API_KEY = os.environ.get("JSATLAS_LLM_API_KEY", "").strip() or str(
    _FILE.get("api_key") or "")
MODELS = _as_list(os.environ.get("JSATLAS_LLM_MODELS", "")) or _as_list(_FILE.get("models"))
CONFIG_PATH = os.environ.get("JSATLAS_LLM_CONFIG", "").strip() or str(
    _FILE.get("config_path") or "")
TIMEOUT = _as_int(os.environ.get("JSATLAS_LLM_TIMEOUT", "").strip() or None,
                  _as_int(_FILE.get("timeout"), _DEFAULT_TIMEOUT))

ENABLE_PROMPT_CACHE = os.environ.get("JSATLAS_LLM_PROMPT_CACHE", "1") != "0"
CACHE_CONTROL_TYPE = os.environ.get("JSATLAS_LLM_CACHE_TYPE", "ephemeral")
MIN_CACHE_TOKENS = int(os.environ.get("JSATLAS_LLM_MIN_CACHE_TOKENS", "1024"))
MAX_CACHE_MARKERS = int(os.environ.get("JSATLAS_LLM_MAX_CACHE_MARKERS", "4"))


def describe() -> str:
    """给 CLI 用的一行配置摘要：来源 + Key 是否配置（不泄露 Key 本身）。"""
    if CONFIG_SOURCE:
        source = CONFIG_SOURCE
    else:
        source = "未找到配置文件（可放 ./jsatlas.config.json 或 ~/.jsatlas/config.json）"
    key_state = "已配置" if API_KEY else "未配置"
    return f"AI 配置来源 {source}；API Key {key_state}；base_url={BASE_URL}"


__all__ = [
    "BASE_URL",
    "API_KEY",
    "MODELS",
    "CONFIG_PATH",
    "TIMEOUT",
    "ENABLE_PROMPT_CACHE",
    "CACHE_CONTROL_TYPE",
    "MIN_CACHE_TOKENS",
    "MAX_CACHE_MARKERS",
    "CONFIG_SOURCE",
    "CONFIG_ERRORS",
    "describe",
]
