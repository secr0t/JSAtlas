"""JavaScript 解析层。

职责边界：
* 只负责把源码变成 AST，以及把 AST 节点变成统一的位置模型；
* 不认识"API"、"参数"、"敏感信息"这些概念，那是 analyzers 的事；
* 不依赖上游 JScanner2 的 logger / config（那会带来建目录和发飞书的副作用）。
"""

from jsatlas.parsing.parser import (  # noqa: F401
    get_parser,
    parser_error,
    parse_bytes,
    parse_text,
    set_parser,
    reset_parser,
)
from jsatlas.parsing.location import (  # noqa: F401
    SourceLocation,
    location_from_node,
    location_from_span,
)

__all__ = [
    "get_parser",
    "parser_error",
    "parse_bytes",
    "parse_text",
    "set_parser",
    "reset_parser",
    "SourceLocation",
    "location_from_node",
    "location_from_span",
]
