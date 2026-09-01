# Sentinel-AI

[![CI](https://github.com/osmankaankars/Sentinel-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/osmankaankars/Sentinel-AI/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Sentinel-AI is an educational proof of concept for deterministic Python AST security rules. It
scans one local Python file, reports narrowly defined patterns, and provides manual review
guidance. It does not call an AI service, use the network, generate patches, or modify source
files.

This project demonstrates how transparent rules can produce reviewable static-analysis results.
It is not a full SAST product and does not establish that scanned code is secure.

## Rules

| ID | Pattern | Reported context |
| --- | --- | --- |
| `SEN001` | A direct `os.system(...)` call | Line, column, and call type |
| `SEN002` | `SELECT`, `INSERT`, `UPDATE`, or `DELETE` in the literal portion of an f-string | Line, column, and matched SQL keyword |
| `SEN003` | A non-empty string or bytes literal assigned to a secret-like variable | Line, column, and variable name |

For `SEN003`, names are split at snake-case and camel-case boundaries. The rule recognizes
`password`, `passwd`, `secret`, or `token` components, plus `key` when paired with a context such
as `api`, `access`, `auth`, `aws`, `private`, or `secret`. Substrings such as `monkey`, `secretary`,
and `tokenizer` are not treated as secret names. Dynamic values such as `os.getenv("API_KEY")` are
not literal-secret findings.

Findings intentionally contain no source snippets or literal values. This reduces the chance of
copying a hard-coded secret into terminal output, logs, or CI artifacts.

## Requirements

- Python 3.11 or newer
- No third-party runtime dependencies

## Usage

```bash
git clone https://github.com/osmankaankars/Sentinel-AI.git
cd Sentinel-AI
python3 sentinel.py vulnerable_app.py
```

The command scans exactly one file and returns:

| Exit code | Meaning |
| --- | --- |
| `0` | The configured rules produced no findings |
| `1` | One or more potential issues require manual review |
| `2` | The file could not be read, decoded, or parsed, or CLI usage was invalid |

Python encoding cookies are honored through `tokenize.open()`, including valid non-UTF-8 source
files. Read, encoding, and syntax failures are reported without printing source contents.

## Development

The test suite is offline and uses only the Python standard library:

```bash
python3 -m unittest discover -s tests -v
```

Formatting and lint checks use Ruff:

```bash
ruff check .
ruff format --check .
```

CI runs the unit tests on Python 3.11, 3.12, and 3.13. Its third-party GitHub Actions are pinned to
full commit SHAs and the workflow has read-only repository permissions.

## Limitations

- Rules are syntactic and do not perform data-flow, dependency, framework, or inter-file analysis.
- `SEN001` intentionally matches direct `os.system` syntax only; imports and aliases are outside its
  scope.
- Findings can be false positives or miss vulnerabilities. A qualified reviewer must validate them.
- Sentinel-AI never remediates or rewrites code automatically.

Use the scanner only on code you are authorized to inspect.

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Osman Kaan Kars.
