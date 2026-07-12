# JWTCheck

**A static analyser and offline token-assessment tool for JSON Web Token (JWT) security in Python.**

JWTCheck detects insecure use of the [PyJWT](https://pyjwt.readthedocs.io/) library in Python source code, and separately decodes and assesses raw JWT tokens without ever contacting a network. It was built as the practical component of an MSc Cyber Security dissertation (University of Surrey, 2026) and adapts the 15 JWT-misuse detection patterns from JWTKey (Xu et al., ESORICS 2023) — originally Java-only — to Python and PyJWT, for which no equivalent native tool previously existed.

The tool has two independent modes:

| Mode | What it does |
|------|--------------|
| `scan` | Static (AST-based) analysis of Python source, flagging 15 classes of PyJWT cryptographic misuse. |
| `analyse` | Decodes and assesses raw JWT tokens offline — header/claim inspection, risk scoring, and optional HMAC secret recovery. |

---

## Quick demo

Scanning the deliberately-insecure [`demo/vulnerable_app.py`](demo/vulnerable_app.py):

```console
$ jwtcheck scan demo/vulnerable_app.py --no-remediation

CRITICAL R01 MissingAlgorithmsParameter
  demo/vulnerable_app.py:21:11
    return jwt.decode(token, secret)
  jwt.decode() is called with no algorithms parameter, allowing the token
  header to select the verification algorithm.
  Weakness: CWE-757

CRITICAL R02 NoneAlgorithmAccepted
  demo/vulnerable_app.py:27:11
    return jwt.decode(token, "k", algorithms=["none"])
  The 'none' algorithm is present in the algorithms list, so an unsigned
  token would be accepted.
  Weakness: CWE-347

HIGH R05 HardcodedSecretEncode
  demo/vulnerable_app.py:14:11
    return jwt.encode(payload, "hardcoded-secret", algorithm="HS256")
  A hardcoded string literal is used as the signing key in jwt.encode().
  Weakness: CWE-798

  ... (R06, R07, R08, R09 also raised)

Summary — 9 finding(s): CRITICAL: 2, HIGH: 3, MEDIUM: 4
```

Findings are colourised by severity in a real terminal, carry the exact
line/column and CWE, and (unless `--no-remediation` is passed) a one-line fix.
Run it yourself after installing — the full output lists all nine findings.

---

## Requirements

- Python **3.9 or newer**
- [PyJWT](https://pypi.org/project/PyJWT/) 2.0+ (installed automatically)

## Installation

Clone the repository and install it as an editable package. This registers the `jwtcheck` command on your `PATH`.

```bash
git clone <repository-url>
cd Jwtcheck

# (recommended) create and activate a virtual environment
python -m venv venv
# Windows PowerShell:
venv\Scripts\Activate.ps1
# macOS / Linux:
source venv/bin/activate

# install the tool
pip install -e .
```

Verify the install:

```bash
jwtcheck --version
```

> If the `jwtcheck` command is not found, you can always run it as a module: `python -m jwtcheck.cli ...`

---

## Usage

### Mode 1 — `scan` (find misuse in source code)

```bash
# scan a single file
jwtcheck scan app.py

# scan a whole project, recursively, skipping test files
jwtcheck scan ./myproject --recursive --exclude-tests

# only show the most serious issues
jwtcheck scan ./myproject -r --severity critical

# machine-readable output for CI / dashboards
jwtcheck scan ./myproject -r --format sarif -o results.sarif
```

**`scan` options**

| Flag | Meaning |
|------|---------|
| `--recursive`, `-r` | Recurse into subdirectories. |
| `--format {text,sarif}` | Output format (default `text`; `sarif` for tooling). |
| `--output`, `-o` | Write to a file instead of stdout. |
| `--severity {critical,high,medium,all}` | Only report findings at or above this level. |
| `--exclude-tests` | Skip `test_*.py`, `tests/` directories, and `conftest.py`. |
| `--no-remediation` | Hide the "how to fix" text. |

### Mode 2 — `analyse` (assess a raw token, offline)

```bash
# assess a token piped in
echo "eyJhbGciOi..." | jwtcheck analyse --stdin

# pull tokens out of a log file
jwtcheck analyse server.log --log

# attempt to recover a weak HMAC secret
jwtcheck analyse token.txt --bruteforce --wordlist rockyou.txt --timeout 60

# JSON output
jwtcheck analyse --stdin --format json
```

**`analyse` options**

| Flag | Meaning |
|------|---------|
| `--stdin` | Read the token from standard input. |
| `--log` | Treat the input as a log file and extract embedded tokens. |
| `--bruteforce` | Attempt HMAC secret recovery (needs `--wordlist`). |
| `--wordlist`, `-w` | Wordlist for brute-forcing. |
| `--timeout` | Brute-force time budget in seconds (default 30). |
| `--format {text,json}` | Output format (default `text`). |
| `--output`, `-o` | Write to a file instead of stdout. |

> **Note:** `analyse` performs all cryptographic work locally. No token or secret ever leaves the machine — this is deliberate, so the tool is safe for incident responders handling live credentials.

---

## Detection rules

`scan` implements 15 rules. Severity reflects exploitability.

| ID | Severity | Detects |
|----|----------|---------|
| R01 | CRITICAL | `jwt.decode()` with no `algorithms` parameter |
| R02 | CRITICAL | `none` algorithm accepted |
| R03 | CRITICAL | Signature verification disabled (`verify_signature=False` / `verify=False`) |
| R04 | CRITICAL | Algorithm confusion — HMAC and asymmetric algorithms mixed |
| R05 | HIGH | Hardcoded secret in `jwt.encode()` |
| R06 | HIGH | Hardcoded secret in `jwt.decode()` |
| R07 | HIGH | Token signed without an `exp` (expiry) claim |
| R08 | MEDIUM | No audience (`aud`) validation |
| R09 | MEDIUM | No issuer (`iss`) validation |
| R10 | HIGH | Excessive token lifetime |
| R11 | CRITICAL | Issuer verification disabled (`verify_iss=False`) |
| R12 | MEDIUM | Excessive clock-skew `leeway` |
| R13 | CRITICAL | Expiry verification disabled (`verify_exp=False`) |
| R14 | HIGH | RSA/PEM key passed as a plain string literal |
| R15 | MEDIUM | Env-var secret with algorithms not pinned to one algorithm |

When signature verification is disabled, JWTCheck raises **only** R03 (the meaningful signal) and suppresses the now-moot R01/R08/R09, to avoid redundant noise on legitimate token-inspection code.

---

## Limitations

JWTCheck is a **lightweight, intraprocedural static analyser**. It deliberately
trades completeness for precision — it prefers to stay silent rather than guess
about values it cannot resolve statically. The following patterns are, by design,
**not** detected, and are documented here rather than left as silent blind spots:

- **Multi-hop variable resolution.** Assignments are tracked one level deep in a
  flat scope (last write wins). `a = SECRET; b = a; jwt.decode(token, b, ...)`
  resolves `b` to `a`, not to `SECRET`, so a hardcoded key laundered through two
  variables is missed. Branch-dependent reassignments (a value set differently in
  two `if` arms) may also resolve to the wrong assignment.
- **Indirection and wrappers.** Only direct `jwt.decode(...)` / `jwt.encode(...)`
  (via a tracked import alias) and `from jwt import decode` calls are matched. A
  decode hidden behind a helper (`self._decode(token)`, `auth.verify(token)`) or
  a functools wrapper is not followed.
- **Dynamically-built arguments.** An `algorithms` list assembled at runtime
  (`.append()`, a comprehension, or returned from a function) resolves to
  "unknown", so the algorithm rules (R01/R02/R04) are not evaluated for it.
- **Non-literal keys and payloads are assumed safe.** To keep false positives
  low, a computed key or a payload that is not a dict literal is treated as
  benign. A genuinely weak key produced at runtime will not be flagged.
- **Environment loads are pattern-matched narrowly.** R15 recognises
  `os.environ.get(...)` / `os.environ[...]`; secrets loaded via `python-dotenv`,
  a settings object, or a config framework are not recognised as env loads.
- **No cross-file/interprocedural dataflow.** Analysis is per-function; a value
  flowing in from another module or caller is not traced.
- **Intent is undecidable statically.** The tool cannot distinguish an attack
  from *deliberate* unverified decoding (inspection tools, "peek-then-verify"
  claim extraction). This is the single source of residual false positives in the
  real-world study (R03), and is discussed in `benchmark/real_world/RESULTS.md`.

These boundaries are typical of a precision-first AST analyser. Closing them would
require taint/dataflow analysis (e.g. a CodeQL-style approach) — noted as future
work in the dissertation.

---

## Development & testing

```bash
pip install -e ".[dev]"
python -m pytest          # runs the full test suite
```

## Evaluation

Reproducible evaluation artefacts live under `benchmark/`:

- **Controlled benchmark** — precision/recall on 28 hand-labelled samples (`benchmark/evaluate.py` → `results.json`).
- **Tool comparison** — JWTCheck vs Bandit vs Semgrep (`benchmark/compare_tools.py` → `tool_comparison.md`).
- **PortSwigger labs** — token-assessment validation (`benchmark/portswigger_eval.py`).
- **Real-world study** — scan of 96 external GitHub projects with full triage and precision figures (`benchmark/real_world/RESULTS.md`).
- **Rule-coverage study** — targeted search confirming all 15 rules fire on real third-party code, 109 findings across 71 repositories (`benchmark/rule_coverage/RULE_COVERAGE.md`).

## Project layout

```
jwtcheck/        the tool (scanner, analyser, brute-forcer, rules, CLI)
tests/           unit tests and labelled fixtures
benchmark/       evaluation scripts and results
```

## Author & licence

Shaikh Zaka ur Rehman — MSc Cyber Security dissertation, University of Surrey (2026).
Released under the MIT licence.
