"""参数字符串解析（逐字迁移自 JScanner2 `request_executor.py`）。

上游 `AISecurityAuditor` 产出的 `params` 是**字符串**（如 `"userId=1&page=2"`），
由这个函数转成字典。模板里的 `"userId": ""` 就来自这里 ——
**没有 `=` 的项赋空字符串**。

JSAtlas 把它单独搬过来，避免为了这一个函数引入整个发包验证模块。
"""

from __future__ import annotations

import json
from typing import Any, Dict


def _parse_params_string(params_str: str) -> Dict[str, Any]:
    """
    解析参数字符串为字典

    支持格式：
    - "key1=value1,key2=value2"
    - "key1=value1&key2=value2"
    - JSON 字符串（兼容）

    Args:
        params_str: 参数字符串

    Returns:
        解析后的参数字典
    """
    if not params_str or not isinstance(params_str, str):
        return {}

    params_str = params_str.strip()
    if not params_str:
        return {}

    if params_str.startswith('{'):
        try:
            parsed = json.loads(params_str)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    params = {}
    separator = ',' if ',' in params_str else '&'

    for item in params_str.split(separator):
        item = item.strip()
        if not item:
            continue

        if '=' in item:
            key, value = item.split('=', 1)
            params[key.strip()] = value.strip()
        else:
            params[item] = ""

    return params

# 保持上游原名的同时给一个不带下划线的别名，方便外部调用
parse_params_string = _parse_params_string

__all__ = ["parse_params_string", "_parse_params_string"]
