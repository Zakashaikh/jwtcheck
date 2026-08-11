# Held-out validation — out-of-sample precision

## Why this study exists

The 96-repository precision figure (96.7%) is a **resubstitution estimate**. The
verification-disabled refinement was derived by analysing the false positives in
those 96 repositories and then measured by re-scanning the same 96. Tuning and
evaluation share a sample, so the figure is optimistically biased by an unknown
amount.

This study applies the tool to **30 repositories it has never seen**, assembled by
`benchmark/fetch_heldout.py` under the same inclusion criterion and explicitly
disjoint from the original 96.

## Headline result

| Metric | 96-repo study (resubstitution) | Held-out (out-of-sample) |
|--------|-------------------------------:|-------------------------:|
| Repositories | 96 | 30 |
| Repositories with findings | 64 | 14 |
| Findings | 332 | 63 |
| True positives | 321 | 51 |
| False positives | 11 | 12 |
| **Precision** | **96.7%** | **81.0%** |

**Out-of-sample precision is 51/63 = 81.0%**, materially below the 96.7%
resubstitution estimate. The gap is the quantity the resubstitution estimate was
concealing, and reporting it is the point of the exercise.

## A defect found, and fixed

The first held-out run produced 66 findings at 77.3% precision. Three of those
false positives shared a single root cause, which turned out to be a genuine bug
in the scanner rather than a judgement call.

`arXiv/arxiv-auth` defines its own wrapper at
`cloud_auth/arxiv/cloud_auth/jwt.py:6`:

```python
def decode(token: str, secret: str):
    data = dict(jwt.decode(token, secret, algorithms=["HS256"]))
```

and imports it in `cloud_auth/arxiv/cloud_auth/fastapi/auth.py:10` as
`from ..jwt import decode`. The scanner reported R01 (missing `algorithms`), R08
and R09 against the wrapper call site, even though the algorithm *is* pinned
inside the wrapper and the real PyJWT call is already reported at `jwt.py:8`.

The cause was in `visit_ImportFrom` (`jwtcheck/scanner.py`):

```python
if node.module and node.module.split('.')[0] == 'jwt':      # before
if node.level == 0 and node.module and ...                  # after
```

Python's AST reports `module == 'jwt'` for both `from jwt import decode`
(`level == 0`, genuine PyJWT) and `from ..jwt import decode` (`level == 2`, a
local `jwt.py`). Without the level check the scanner bound a local module's
`decode` as PyJWT's and analysed every call to it as a bare `jwt.decode()`.

Adding the level check removed exactly those three false positives, changed
nothing else in the held-out set, and left the 96-repository study unchanged at
332 findings. Regression tests covering both the relative and absolute import
forms are in `tests/test_scanner.py`.

The defect only manifests in projects that contain a local module named `jwt.py`
imported relatively. That is why 96 repositories never surfaced it and one
held-out repository did — a concrete demonstration of what out-of-sample
validation buys.

## Why precision is still below 96.7% — two FP classes the 96 never contained

The 96-repository study found exactly one FP phenomenon: intentional unverified
decoding. After the scanner fix, the held-out sample's 12 remaining false
positives divide evenly into two classes, neither of which appears in the
original study.

### 1. Demonstration and tutorial code (6 FPs)

`alpersonalwebsite/flask-auth0-authentication-authorization` —
`extras/jwt-encode-decode.py` is a teaching script: it encodes
`{'message': 'Hello World!'}` with the secret `'this is the secret'`, prints the
token, decodes it, and prints the result. Six rules fire correctly on the syntax
(R01, R05, R06, R07, R08, R09). No security decision exists anywhere in the file,
so no weakness exists either.

### 2. Post-verification peeks (6 FPs)

`themanoj-025/UNION-BANK-` decodes a refresh token a second time with
`options={"verify_exp": False}` at `main.py:1619` and `v2.py:296`, solely to
extract the token ID for revocation during rotation. Both sites sit behind
`verify_refresh_token()`, which has already validated signature, expiry and
revocation state. R13, R08 and R09 at these sites all report validation that
demonstrably happened upstream.

R04 at `v2.py:296` is scored TP despite the same gating: `algorithms=["RS256",
"HS256"]` mixes HMAC and RSA families, which is a latent defect independent of
current reachability. This is the single most disputable verdict in the set.

## Correct scoping — a check that passed

`chris83254/fastapi-boilerplate` calls `jwt.decode(...)` at
`app/core/security.py:27` with neither audience nor issuer, and reported nothing.
That is correct: the file imports `from jose import JWTError, jwt`, so it is
python-jose, not PyJWT, and out of scope. The scanner resolves provenance
correctly for the module name; the defect above was specific to unqualified
function names.

## Per-repository breakdown

| Repository | Findings | TP | FP |
|------------|---------:|---:|---:|
| arXiv/arxiv-auth | 11 | 11 | 0 |
| themanoj-025/UNION-BANK- | 11 | 5 | 6 |
| Somtochukwu-Sabastine/Secure-Authentication-System | 8 | 8 | 0 |
| Dhruv-gif-hub/FastAPI-auth-service | 6 | 6 | 0 |
| alpersonalwebsite/flask-auth0-authentication-authorization | 6 | 0 | 6 |
| IcarusSec/ICARUS-Lab | 5 | 5 | 0 |
| Werner1126/smart-learning-platform | 2 | 2 | 0 |
| Aadi2104/olympiad-connect | 2 | 2 | 0 |
| ravitejakotrike/AI-Based-Verilog-TestBench-Generator | 2 | 2 | 0 |
| arakium/ExpenseTrackerAPI | 2 | 2 | 0 |
| harshadx27/Cafe-REST-API | 2 | 2 | 0 |
| jayforge-dev/flask-auth-crud | 2 | 2 | 0 |
| mzulqarnain-ceh/user-auth-api | 2 | 2 | 0 |
| Gloriazhou1127/salon-event-system | 2 | 2 | 0 |
| **Total** | **63** | **51** | **12** |

All 12 false positives fall in just 2 of the 14 repositories.

## Precision by rule

| Rule | Flagged | TP | FP | Precision | 96-repo precision |
|------|--------:|---:|---:|----------:|------------------:|
| R01 MissingAlgorithmsParameter | 1 | 0 | 1 | 0.0% | 96.4% |
| R04 AlgorithmConfusionHsRs | 1 | 1 | 0 | 100.0% | — |
| R05 HardcodedSecretEncode | 3 | 2 | 1 | 66.7% | — |
| R06 HardcodedSecretDecode | 4 | 3 | 1 | 75.0% | — |
| R07 MissingExpClaim | 2 | 1 | 1 | 50.0% | — |
| R08 MissingAudienceValidation | 26 | 23 | 3 | 88.5% | 100% |
| R09 MissingIssuerValidation | 24 | 21 | 3 | 87.5% | 100% |
| R13 ExpiryVerificationDisabled | 2 | 0 | 2 | 0.0% | — |
| **Overall** | **63** | **51** | **12** | **81.0%** | 96.7% |

R08 and R09 were 100% precise across the 96 repositories and are the reason the
headline figure held up there. Out of sample they fall to ~88%, which accounts
for most of the remaining decline. The low-count rules (R01, R07, R13 at one or
two findings each) carry no statistical weight and should not be read as rule
quality.

## Sensitivity

| Scenario | Precision |
|----------|----------:|
| As scored | **81.0%** (51/63) |
| R04 at `v2.py:296` scored FP instead of TP | 79.4% (50/63) |
| Peek-site R08/R09 scored TP instead of FP | 87.3% (55/63) |
| `IcarusSec/ICARUS-Lab` excluded as a purpose-built vulnerable app | 79.3% (46/58) |

The defensible range is roughly **79–87%**.

## What this study cannot show

**The held-out set contains zero R03 findings.** R03
(`SignatureVerificationDisabled`) is the rule at the centre of the
verification-disabled refinement, and no repository in the sample disables
signature verification. The refinement therefore never fired, and this study
**cannot validate it**. It measures the scanner's out-of-sample precision as a
whole; it does not measure whether the refinement generalises. A future held-out
set should be stratified to guarantee R03 sites are present.

Recall is not computable here, for the same reason it was not computable in the
96-repo study: there is no ground-truth inventory of every JWT weakness across 30
external repositories.

## Reproduce

```bash
python benchmark/fetch_heldout.py                 # rebuild the 30-repo sample
python benchmark/run_real_world.py --manifest benchmark/heldout_repos.json \
    --out benchmark/heldout                       # rescan
```

TP/FP verdicts were assigned by reading the source at each site. The
classification rule is the one used for the 96-repo study: a finding is a true
positive when the flagged pattern is present *and* the code path feeds an
authentication or authorisation decision; a false positive when the pattern is
present but the code makes no security decision, or the validation it names
demonstrably happens elsewhere.
