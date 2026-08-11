# Third sample — R03-stratified application validation

## Purpose

The held-out sample (`benchmark/heldout/`) contained no R03 findings, so the
verification-disabled refinement never activated and could not be validated.
This sample is stratified so that every repository disables signature
verification somewhere, and filtered so that only applications remain.

## Construction

| Stage | Repos |
|-------|------:|
| Candidates examined | ~600 |
| Had no PyJWT usage | 275 rejected |
| Had PyJWT but never disable verification | 288 rejected |
| Excluded as JWT/auth libraries (automated) | 36 |
| Survived automated filtering | 21 |
| Excluded on manual review (see manifest) | 10 |
| **Final sample** | **11** |

The pool was exhausted at 21, not the 30 requested. Two repositories were
deliberately retained despite being non-production code: a teaching lab
(`Writeup-DB/JWT-101-Lab`) and a coding-challenge submission
(`tatiane-ss/backend-challenge-tssgaec`).

**Base rate.** Only 30 of 322 PyJWT-using repositories examined (9.3%) disable
signature verification anywhere. This is the central empirical finding of the
study and it explains why the first held-out draw contained no R03 at all.

## Results

46 findings across 6 of the 11 repositories; 6 of 15 rules fired
(R03, R05, R06, R07, R08, R09).

| Measure | Findings | TP | FP | Precision |
|---------|---------:|---:|---:|----------:|
| **Overall** | 46 | 40 | 6 | **87.0%** |
| Excluding the teaching lab | 22 | 17 | 5 | 77.3% |
| **R03 only** | 9 | 4 | 5 | **44.4%** |
| R03 excluding the teaching lab | 7 | 2 | 5 | 28.6% |

`Writeup-DB/JWT-101-Lab` contributes 24 of the 46 findings (52%) and 23 of the
40 true positives. Any overall figure is substantially a measurement of that one
repository, which is why the excluding-lab row is reported alongside it.

**Contamination note.** These figures follow a scanner fix applied *after* the
triage was complete (see "A third defect", below). The pre-fix figures were 47
findings at 85.1% overall and 40.0% for R03. The fix removed exactly one
false positive — the vendored dependency — and altered nothing else; the
held-out sample still reports 63 findings and the 96-repository study still
reports 332. The change is therefore small and fully accounted for, but the
post-fix number is no longer a clean out-of-sample measurement, and 85.1% /
40.0% are the uncontaminated values.

## The R03 result

R03 is by a wide margin the least precise rule measured anywhere in this
dissertation: **40% overall, 25% once the artificial teaching lab is removed.**
Every other rule in this sample exceeded 80%.

The six R03 false positives, each verified by reading the source:

| Site | Why it is not a weakness |
|------|--------------------------|
| `OPSKP/PyJWT` `vc_did.py:88` | Peek-then-verify. Decodes unverified only to read `iss`, resolves the issuer DID to fetch the public key, then verifies properly at line 96. The documented pattern for dynamic key resolution. |
| `alexfofanov/rbac-service` `authentication/utils.py:22` | Reads `exp` from an unverified token to compute a Redis TTL for a revocation blocklist. A forged claim can only affect how long the attacker's own token stays blocked, and the exception path blocks it regardless. |
| `PradeepMalineni/PYJWT` `security/auth.py:81, 141` | Builds a diagnostic `token_info` dictionary, explicitly commented "Extract token claims (unverified)". Feeds logging, not authorisation. |
| `wuhonglei/chat-agent` `backend/app/core/jwt.py:108` | Method named `decode_token_without_verification`, docstring states "for debugging only". |
| `hkcoder18/2026-May-01` `myenv/Lib/site-packages/redis/auth/token.py:89` | Not the project's code. A vendored virtualenv committed to the repository; this is the `redis` package's own source. See the defect below. |

Five of the six are the same phenomenon identified in the earlier samples: the
decoded value never reaches a security decision, or is verified immediately
afterwards. The sixth is a scanner defect.

This is the empirical confirmation of the base-rate argument. R03 fires
correctly on the syntax almost every time, but the population of code that
disables signature verification is dominated by code that has a legitimate
reason to do so — key resolution, revocation bookkeeping, diagnostics and
debugging.

## A third defect found

`hkcoder18/2026-May-01` commits its virtualenv as `myenv/`. The scanner's
`_SKIP_DIRS` set covers `venv`, `.venv`, `env` and `node_modules`, but matches
on the directory's *name*, so a virtualenv named anything else is scanned in
full — including every installed dependency's source.

The fix is to skip `site-packages` and `dist-packages` by name, which holds
regardless of what the enclosing virtualenv is called. Both were added to
`_SKIP_DIRS` in `jwtcheck/scanner.py`, with a regression test in
`tests/test_scanner.py` that vendors a package under `myenv/Lib/site-packages/`
and asserts only the application's own file is reported.

Applied after triage, the fix removed exactly the one predicted false positive.
`hkcoder18/2026-May-01` now reports no findings at all, since its only finding
came from the vendored package. Neither regression sample moved: the held-out
set still reports 63 findings, the 96-repository study still 332.

## Interpretation and limits

This sample is small (11 repositories, 47 findings), heavily concentrated
(51% from one teaching lab) and cannot be grown — the candidate pool was
exhausted. **The overall 85.1% should not be quoted as a third precision
figure.** It is not comparable with the 96-repo study or the held-out study,
because the sampling frame is deliberately different.

What it does establish, and what no other study here could:

1. R03 precision on unseen application code is **40%**, or 25% excluding
   artificial code — the weakest rule measured.
2. The verification-disabled refinement does not repair this. The refinement
   suppresses R01/R08/R09 at R03 sites; it leaves R03 itself firing, and R03
   is the finding that is usually wrong.
3. A clean 30-repository sample of ordinary applications that disable signature
   verification **cannot be assembled**, because at a 9.3% base rate, filtered
   for libraries and tools, not enough exist.

Several verdicts are judgement calls and are recorded as such. The most
disputable is `OPSKP/PyJWT`, a verifiable-credential demonstration whose code
nonetheless implements real verification logic; its two `vc_tsl.py` R03
findings are scored **true positives** because `verify_credential_status`
decides credential validity from unverified claims with no subsequent
verification — unlike `vc_did.py:88`, which verifies immediately afterwards.

## Reproduce

```bash
python benchmark/fetch_heldout.py --target 30 --require-r03 --exclude-libraries \
    --out-dir third_targets_apps --manifest benchmark/third_repos_apps.json \
    --exclude-manifest benchmark/heldout_repos.json
python benchmark/run_real_world.py --manifest benchmark/third_repos_curated.json \
    --out benchmark/third_curated
```

Manual exclusions and the curation rationale are recorded in
`benchmark/third_repos_curated.json`.
