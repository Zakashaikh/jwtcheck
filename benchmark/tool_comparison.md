# Tool Comparison — JWTCheck vs Bandit vs Semgrep

Corpus: 15 vulnerable + 4 safe fixtures (tests/fixtures/).

## Detection on vulnerable fixtures (higher = better)

| Tool | JWT misuses detected | Coverage |
|------|----------------------|----------|
| **JWTCheck** | 15/15 | 100% |
| Bandit | 0/15 | 0% |
| Semgrep (p/python) | 3/15 | 20% |

## False positives on safe fixtures (lower = better)

| Tool | False positives |
|------|-----------------|
| **JWTCheck** | 0/4 |
| Bandit | 0/4 |
| Semgrep | 0/4 |

## Per-file detail

| File | Category | JWTCheck | Bandit | Semgrep |
|------|----------|----------|--------|---------|
| r01_no_algorithms.py | vulnerable | R01,R08,R09 | — | — |
| r02_none_algorithm.py | vulnerable | R02,R06,R08,R09 | — | jwt-python-none-alg |
| r03_verify_signature_false.py | vulnerable | R03 | — | unverified-jwt-decode |
| r04_algorithm_confusion.py | vulnerable | R04 | — | — |
| r05_hardcoded_secret_encode.py | vulnerable | R05 | — | jwt-python-hardcoded-secret |
| r06_hardcoded_secret_decode.py | vulnerable | R06 | — | — |
| r07_no_exp_claim.py | vulnerable | R07 | — | — |
| r08_no_audience.py | vulnerable | R08 | — | — |
| r09_no_issuer.py | vulnerable | R09 | — | — |
| r10_excessive_lifetime.py | vulnerable | R10 | — | — |
| r11_verify_iss_false.py | vulnerable | R11 | — | — |
| r12_excessive_leeway.py | vulnerable | R12 | — | — |
| r13_verify_exp_false.py | vulnerable | R13 | — | — |
| r14_rsa_string_key.py | vulnerable | R06,R14 | — | — |
| r15_env_secret_multi_alg.py | vulnerable | R04,R15 | — | — |
| bytes_decode.py | safe | — | — | — |
| correct_usage.py | safe | — | — | — |
| no_jwt.py | safe | — | — | — |
| str_encode.py | safe | — | — | — |

Note: Bandit and Semgrep's standard Python rulesets contain no JWT-cryptographic-misuse rules. Any detections shown are generic rules (e.g. Bandit B105 hardcoded password) that incidentally overlap a JWT issue, not JWT-aware analysis.