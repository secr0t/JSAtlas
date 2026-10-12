---
name: jsatlas-scan
description: Analyze JavaScript for API attack surface and hardcoded secrets with JSAtlas. Use when the user asks to scan or analyze a JS file or URL for API endpoints, request parameters, base URLs, or secrets like tokens and keys. Do not use for non-JavaScript files or when the user wants to actively send requests to discovered APIs.
---

# JSAtlas Scan

> **Deployment note (not Trae-specific):** this skill is a platform-agnostic instruction
> bundle. Copy this folder (`jsatlas-scan/`) into the skills directory of whichever agent
> you use — e.g. Claude Code `~/.claude/skills/`, Cline, or a red-team agent's custom skills
> directory. The commands and contract below are plain CLI facts; they do not depend on any
> particular agent framework.

JSAtlas is a JavaScript security intelligence engine. It extracts a requestable API list
(`apis`) and a suspicious-secret list (`secrets`) from JS source in one run, and prints a
stable JSON document to stdout. This skill tells you how to invoke it correctly and how to
interpret the output. Full parameter reference: `references/cli-contract.md`.

## 1. Decide the input type

| Input | What to do |
| --- | --- |
| Local file | Pass the path directly: `python -m jsatlas <path>` |
| Remote URL | Pass the URL directly (JSAtlas performs one GET for it) |
| Code snippet in chat | Write it to a temp file first, then pass the path |
| Non-JavaScript file | Do not use this skill |

## 2. Choose the mode

| Need | Command | Result |
| --- | --- | --- |
| API endpoints only | `python -m jsatlas <target> --mode api` | `{"apis": [...], "secrets": []}` |
| Secrets only | `python -m jsatlas <target> --mode secret` | `{"apis": [], "secrets": [...]}` |
| Everything (default) | `python -m jsatlas <target>` | Both populated |

Finer control: `--analyzers <name...>` overrides `--mode`. List names with
`python -m jsatlas --list-analyzers`.

## 3. Invocation templates

Local:

```bash
python -m jsatlas app.js -o result.json --validate
python -m jsatlas https://example.com/static/app.js --mode api --indent 0
```

Docker (when JSAtlas runs in a container):

```bash
docker run --rm -v "${PWD}:/in" jsatlas /in/app.js --mode api --indent 0
```

LLM-backed steps (secret verification, parameter Level 2/3) need a key. Without one the
analysis still runs and degrades to deterministic results, so do not fail the task — just
note that AI verification was skipped.

```bash
JSATLAS_LLM_API_KEY=sk-xxx python -m jsatlas app.js
```

## 4. Output contract (always true)

- **stdout carries JSON only.** Logs and warnings go to stderr. Parse stdout only.
- Top level is **always exactly two keys**: `apis` and `secrets`. Unused side is `[]`,
  never missing — no per-mode parsing needed.
- `apis` items: `path`, `method` (uppercase), `params?`, `source`. Sorted by `(path, method)`.
- `secrets` items: `value`, `type`, `risk_level`, `test_suggestion`, `source`.
  Sorted High → Medium → Low.
- Exit codes: `0` success; `1` partial failure (batch) or `--validate` failed, stdout still
  valid for the successful items; `2` usage error or a single target could not be fetched.
- Same input twice → byte-identical output. Usable for diffing.

## 5. Interpretation pitfalls

- **`params` key missing = parameters unknown, not "no parameters".** Never send an
  unparameterized request on that basis. Present values may still be empty strings.
- **`method: ""` means undetermined**, do not assume GET.
- **`apis` never contains** absolute URLs (`http(s)://`, `//`), static-resource suffixes
  (`.css`, `.png`, `.svg`, `.map`, ...), or baseURL write points like
  `axios.defaults.baseURL`. Those are filtered by design, so do not ask for them back.
- **`type: "high_entropy_value"` with `risk_level: "Low"` means the item was NOT
  LLM-verified** (no key or verification failed). Treat confidence as low.
- **`secrets: []` has two meanings**: no candidates at all (`candidates: 0`) vs candidates
  all rejected by the LLM (`candidates: N, kept: 0, ai_used: true`). Only the inner
  statistics object distinguishes them; CLI JSON output does not include the statistics
  block.

## 6. Boundaries

- JSAtlas does **not** send requests to discovered APIs and does **not** declare findings
  as vulnerabilities. It produces intelligence and evidence. Actual request validation and
  exploit path selection are downstream responsibilities.
- Multi-target runs merge into one list; each item carries its own `source`.
- Validation against the formal schema: use `--validate` or `schemas/report-v1.schema.json`.

Reference: [CLI contract and full parameter table](references/cli-contract.md)
