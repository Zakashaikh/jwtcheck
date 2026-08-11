# Tool Comparison — JWTCheck vs Bandit vs Semgrep

Corpus: 16 vulnerable + 5 safe fixtures (tests/fixtures/).

## Detection on vulnerable fixtures (higher = better)

| Tool | JWT misuses detected | Coverage |
|------|----------------------|----------|
| **JWTCheck** | 15/16 | 94% |
| Bandit | 0/16 | 0% |
| Semgrep (p/python) | 0/16 | 0% |

## False positives on safe fixtures (lower = better)

| Tool | False positives |
|------|-----------------|
| **JWTCheck** | 0/5 |
| Bandit | 0/5 |
| Semgrep | 0/5 |

## Per-file detail

| File | Category | JWTCheck | Bandit | Semgrep |
|------|----------|----------|--------|---------|
| __pycache__ | vulnerable | — | — | — |
| r01_no_algorithms.py | vulnerable | R01,R08,R09 | — | — |
| r02_none_algorithm.py | vulnerable | R02,R06,R08,R09 | — | — |
| r03_verify_signature_false.py | vulnerable | R03 | — | — |
| r04_algorithm_confusion.py | vulnerable | R04 | — | — |
| r05_hardcoded_secret_encode.py | vulnerable | R05 | — | — |
| r06_hardcoded_secret_decode.py | vulnerable | R06 | — | — |
| r07_no_exp_claim.py | vulnerable | R07 | — | — |
| r08_no_audience.py | vulnerable | R08 | — | — |
| r09_no_issuer.py | vulnerable | R09 | — | — |
| r10_excessive_lifetime.py | vulnerable | R10 | — | — |
| r11_verify_iss_false.py | vulnerable | R11 | — | — |
| r12_excessive_leeway.py | vulnerable | R12 | — | — |
| r13_verify_exp_false.py | vulnerable | R13 | — | — |
| r14_rsa_string_key.py | vulnerable | R14 | — | — |
| r15_env_secret_multi_alg.py | vulnerable | R04,R15 | — | — |
| __pycache__ | safe | — | — | — |
| bytes_decode.py | safe | — | — | — |
| correct_usage.py | safe | — | — | — |
| no_jwt.py | safe | — | — | — |
| str_encode.py | safe | — | — | — |

Note: Bandit's default ruleset contains no JWT-specific checks; its detections here are generic rules (e.g. B105 hardcoded password) that incidentally overlap a JWT issue. Semgrep's `p/python` pack DOES ship JWT-specific rules (`jwt-python-none-alg`, `jwt-python-hardcoded-secret`, `unverified-jwt-decode`), which is what it detects above. The gap is therefore one of coverage, not of existence: Semgrep covers 3 of the 15 misuse patterns catalogued here, with no coverage of algorithm confusion, claim validation, leeway configuration, or key-material handling.