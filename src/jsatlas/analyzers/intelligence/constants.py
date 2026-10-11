"""情报分析用的规则常量。

来源：JScanner2 `config/scanner_rules.py`（第 9-167 行），逐字复制。

为什么整段复制而不是 import 上游 config：
上游 `config` 包在 import 时会读取配置文件、初始化全局配置对象，
这会把核心分析器重新绑回上游运行环境。JSAtlas 只需要这些**纯数据**，
因此直接内联，并在注释中标注原始行号，便于后续核对是否分叉。

未复制的部分：`REQUEST_HEADERS`、`SUPPORTED_REQUEST_METHODS`、`MAX_RETRY_PER_API`
等与"发包验证"相关的常量 —— 那属于首期明确不迁移的能力。
"""

from typing import List, Set

# ---- 原 scanner_rules.py:9-37 ----
# 需要排除的代码上下文：字符串出现在这些上下文里时通常不是敏感信息
EXCLUDED_CONTEXT_PATTERNS: Set[str] = {
    # 控制台输出
    'console.log', 'console.warn', 'console.error', 'console.info', 'console.debug',
    # 浏览器弹窗
    'alert(', 'confirm(', 'prompt(',
    # 日志框架
    'logger.log', 'logger.debug', 'logger.info', 'logger.warn', 'logger.error',
    # 模块导入/导出
    'import ', 'require(', 'export ',
    # DOM 查询方法
    'getElementById', 'querySelector', 'querySelectorAll',
    'getElementsByTagName', 'getElementsByClassName',
    # DOM 操作方法
    'createElement', 'appendChild', 'innerHTML', 'textContent',
    # jQuery/前端框架方法
    '.css(', '.html(', '.text(', '.val(', '.attr(',
    # HTML 标签
    '<div', '<span', '<a ', '<img', '<link', '<script', '<style',
    # 浏览器对象属性
    'window.location', 'document.cookie', '_sentryDebugIds',
}

# ---- 原 scanner_rules.py:45-64 ----
EXCLUDED_LITERAL_VALUES: Set[str] = {
    'false', 'undefined', 'delete',
    'green', 'white', 'black', 'gray', 'grey', 'color',
    'home', 'index', 'login', 'logout',
    'register', 'signup', 'signin',
    'user', 'admin', 'dashboard',
    'header', 'footer', 'sidebar',
    'submit', 'reset', 'button',
    'input', 'form',
    'https', 'localhost', 'base64', 'unicode',
}

# ---- 原 scanner_rules.py:72-85 ----
# 命中则提高"这是敏感信息"的优先级
SENSITIVE_KEYWORD_SET: Set[str] = {
    'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
    'credential', 'cert', 'jwt', 'bearer',
    'api', 'access', 'private', 'private_key',
    'session', 'cookie', 'csrf', 'xsrf',
    'config', 'setting', 'env', 'environment',
}

# ---- 原 scanner_rules.py:116-121 ----
HTTPX_STATIC_EXTENSIONS: List[str] = [
    '.aac', '.apk', '.css', '.csv', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.js', '.json', '.m4v', '.map', '.mp3', '.mp4',
    '.otf', '.png', '.svg', '.swf', '.ttf', '.txt', '.wav', '.webp',
    '.woff', '.woff2', '.xls', '.xlsx', '.xml', '.html', '.htm',
]

# ---- 原 scanner_rules.py:150-159 ----
SECRET_DETECTION_BLACKLIST: List[str] = [
    "ABCDEFGHIJKLMNOP",
    "abcdefghijklmnop",
    "123456789",
    "0000000000",
    "&lt;",
    "I18N",
    ".",
    "/",
]

# ---- 原 scanner_rules.py:163-167 ----
# JS/Web 技术词表：用于统计评分里的 P 特征，命中说明这个值"像正常单词"而非随机密钥
WEB_TECHNICAL_WORDS: Set[str] = {
    'const', 'json', 'facebook', 'webpack', 'redis', 'params',
    'bitbucket', 'django', 'admin', 'github', 'href',
    'gitlab', 'config', 'laravel', "microsoft", "I18N",
}
