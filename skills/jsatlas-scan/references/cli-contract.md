# JSAtlas CLI contract and parameter reference

Loaded on demand when exact flags, exit semantics, or output shape details are needed.
Keep the skill body (SKILL.md) as the primary reading; this file is the source of truth
for exact values.

## CLI usage

```
python -m jsatlas [target ...] [options]
```

Installed console entry point: `jsatlas` (equivalent to `python -m jsatlas`).

## Parameters (verified against src/jsatlas/cli.py)

| Flag | Type / default | Purpose |
| --- | --- | --- |
| `target` | positional, `nargs="*"` | Files and/or URLs, mixable. Merged into one report |
| `-o, --out` | path | Write JSON to file; stdout when omitted |
| `--indent` | int, default 2 | JSON indentation; `0` for compact output |
| `--analyzers` | list | Run only named analyzers; overrides `--mode` |
| `--mode` | `all`/`api`/`secret`, default `all` | Task-level mode. `api` = surface+parameters+context; `secret` = intelligence only |
| `--list-analyzers` | flag | Print registered analyzers and exit |
| `--validate` | flag | Validate output structure/Schema; fail non-zero on error |
| `--proximity-link` | int, default 0 | Proximity linking behavior (0 = off) |
| `--max-context-targets` | int, default 0 | Cap context restoration to N APIs (0 = unlimited) |
| `--timeout` | float | Remote read timeout in seconds (fetch group) |
| `--max-bytes` | int | Remote byte cap (default unlimited) |
| `--header` | append, `K: V` | Repeatable custom request header |
| `--insecure` | flag | Skip TLS verification |
| `--workers` | int, default 4 | Concurrency for multiple URLs |
| `-v, --verbose` | flag | Emit logs |
| `--version` | flag | Print version |

## LLM configuration (optional; degrades gracefully)

| Variable | Purpose |
| --- | --- |
| `JSATLAS_LLM_API_KEY` | Gateway API key |
| `JSATLAS_LLM_BASE_URL` | OpenAI-compatible base URL (default DashScope compatible mode) |
| `JSATLAS_LLM_MODELS` | Comma-separated model names |
| `JSATLAS_LLM_TIMEOUT` | Per-request timeout seconds (default 30) |

Without a key the pipeline still runs: LLM steps (secret verification, parameter
Level 2/3) degrade to deterministic fallbacks and outputs are marked with
`ai_verified=False`. A warning is printed to stderr. Do not treat this as a failure.

## Exit codes

| Code | Meaning | Recommended next action |
| --- | --- | --- |
| 0 | Success | Parse stdout |
| 1 | Batch partial failure, or `--validate` failed | Read stderr; results for successful targets still valid |
| 2 | Usage error, single target fetch failure, or empty target | Read stderr, fix input, retry |

## Output shape (always exactly two top-level keys)

```json
{
  "apis": [
    {
      "path": "/api/v1/user/detail",
      "method": "POST",
      "params": { "userId": "", "page": "1" },
      "source": "https://example.com/static/app.js"
    }
  ],
  "secrets": [
    {
      "value": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
      "type": "high_entropy_value",
      "risk_level": "Low",
      "test_suggestion": "...",
      "source": "https://example.com/static/config.js"
    }
  ]
}
```

### Field semantics

| Field | Meaning | When absent |
| --- | --- | --- |
| `path` | Request path (or full URL) | Never absent; item omitted otherwise |
| `method` | HTTP method, uppercase | Empty string — never guessed as GET |
| `params` | Param name → literal default | **Key omitted entirely** = unknown, not no-args |
| `source` | Origin URL or local path | Empty string for pure-text input |
| `secrets[].type` | Subtype (see below) | — |
| `secrets[].risk_level` | High / Medium / Low, sorted that way | — |
| `secrets[].test_suggestion` | Deterministic guidance, not AI text | — |

### Filtering guarantees for `apis`

Items are excluded by design:

- Absolute URLs — `http(s)://` and protocol-relative `//` (aligned with upstream gate)
- Static-resource suffixes: `.css`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`,
  `.woff`, `.woff2`, `.ttf`, `.eot`, `.mp4`, `.webm`, `.mp3`, `.map`, etc.
- baseURL write points (e.g. `axios.defaults.baseURL = "..."`) — extracted separately by
  `surface.base_url`, never listed as callable APIs

### `secrets[].type` values

| type | Determination | Risk |
| --- | --- | --- |
| `high_entropy_value` | Statistical entropy + tokenization scoring, **no LLM review** | Low |
| LLM-returned `secret_type` | Scoring hit then LLM classification | Per model |

## Registered analyzers

| name | dimension | role |
| --- | --- | --- |
| `surface.path_candidates` | surface | AST string literals → relative API paths, method inference; filters absolute URLs and static suffixes |
| `surface.base_url` | surface | baseURL / apiBase write points |
| `context.api_context` | context | wrapper function, callers, param-score signal |
| `parameters.explicit_params` | parameters | query strings, path-template placeholders, body object keys and literal values |
| `parameters.upstream_pipeline` | parameters | Upstream orchestration chain: blacklist → AST context → Level 2 name → Level 3 value |
| `intelligence.upstream_secret` | intelligence | Upstream chain: HTML strip → format → line slice → entropy/tokenize scoring → AST context → LLM review |

Mode mapping: `api` = surface + parameters + context; `secret` = intelligence;
`all` = everything.
