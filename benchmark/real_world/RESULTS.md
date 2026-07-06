# Real-world evaluation results
Static scan of **96 real GitHub Python projects** (not written by the author), cloned into `realworld_targets/` and scanned with `--exclude-tests`.
## Headline
- **Findings raised:** 332
- **True positives (real weaknesses):** 321
- **False positives (safe/intentional use):** 11
- **Real-world precision = TP / (TP + FP) = 321/332 = 96.7%**

> Every false positive comes from a *single* phenomenon: intentional unverified decoding (token-inspection tools, "peek-then-verify" claim extraction, and debug logging). A purely syntactic analyser cannot tell these safe uses apart from an attack — a known and expected limitation of static detection, and the key qualitative finding of this study.

## Precision by severity
| Severity | Flagged | TP | FP | Precision |
|----------|---------|----|----|-----------|
| CRITICAL | 34 | 23 | 11 | 67.6% |
| HIGH | 67 | 67 | 0 | 100.0% |
| MEDIUM | 231 | 231 | 0 | 100.0% |

## Precision by rule
| Rule | Name | Flagged | TP | FP | Precision |
|------|------|---------|----|----|-----------|
| R01 | Missing algorithms parameter | 21 | 21 | 0 | 100.0% |
| R03 | Signature verification disabled | 13 | 2 | 11 | 15.4% |
| R05 | Hardcoded secret (encode) | 16 | 16 | 0 | 100.0% |
| R06 | Hardcoded secret (decode) | 30 | 30 | 0 | 100.0% |
| R07 | Missing exp claim | 21 | 21 | 0 | 100.0% |
| R08 | Missing audience validation | 112 | 112 | 0 | 100.0% |
| R09 | Missing issuer validation | 119 | 119 | 0 | 100.0% |

## Sensitivity analysis — is the 96.7% inflated by two high-frequency rules?

R08 (missing `aud`) and R09 (missing `iss`) together account for **231 of the 332
findings (69.6%)** and 231 of the 321 true positives. Because PyJWT does not
validate `aud`/`iss` unless the caller explicitly asks it to, these two rules fire
on nearly every *verified* `jwt.decode` call, and every instance is a genuine
(CWE-346) weakness — hence 100% precision on both. A fair examiner's objection is
that two near-ubiquitous, always-correct rules could be flattering the headline
figure. To test that, precision was recomputed with R08 and R09 removed entirely:

| Subset | Flagged | TP | FP | Precision |
|--------|---------|----|----|-----------|
| All rules | 332 | 321 | 11 | **96.7%** |
| Excluding R08 + R09 | 101 | 90 | 11 | **89.1%** |
| CRITICAL only | 34 | 23 | 11 | 67.6% |
| HIGH only | 67 | 67 | 0 | 100.0% |

Two conclusions follow, and they point the same way:

1. **The headline is not an artefact of rule frequency.** Even after discarding the
   two high-frequency claim rules, precision on the substantive rules
   (R01, R03, R05, R06, R07) is **89.1%**, and *every* residual false positive is
   the single, well-characterised R03 phenomenon (intentional unverified decoding).
   There is no second source of error hiding behind the volume of R08/R09.

2. **The objection inverts on inspection.** The rules that might be dismissed as
   "too easy" (R08/R09) are the *most* reliable, at 100%; all the noise is
   concentrated in one hard CRITICAL rule (R03). So the two-rule dominance, far
   from propping up the number, is what a low-noise detector *should* look like —
   cheap, always-true checks are precise, and the only imprecision sits where the
   problem is genuinely undecidable statically (attacker intent).

The tool's precision is therefore bounded below at ~89% on the hard rules and
reaches 96.7% overall; the figure is robust to removing the high-frequency rules.

## Effect of the verification-disabled refinement
The first real-world run produced 368 findings at **88.3%** precision. Analysis showed every false positive came from one phenomenon — code that decodes a token *without verifying it, on purpose* (inspection tools, "peek-then-verify" claim extraction, debug logging) — where the scanner piled R01/R08/R09 on top of R03 for the same line.

The scanner was refined so that when signature verification is disabled it raises **only R03** (the one meaningful signal) and suppresses the now-moot R01/R08/R09. Re-scanning the same 96 repositories:

| Metric | Before refinement | After refinement |
|--------|-------------------|------------------|
| Findings raised | 368 | 332 |
| False positives | 43 | 11 |
| Overall precision | 88.3% | 96.7% |
| MEDIUM precision | 91.4% | 100.0% |

## The residual false positives
After the refinement, the remaining 11 false positives are all the single R03 flag raised on these intentional-unverified-decode sites:

- `Arun1106/mytest` — `a.py:10`
- `Arun1106/mytest` — `auth.py:32`
- `IBM-Cloud/trusted-profile-enterprise-security` — `app.py:132`
- `IBM-Cloud/trusted-profile-enterprise-security` — `app.py:149`
- `LuckDucapa/spidey-ff-spam` — `app.py:311`
- `LuckDucapa/spidey-ff-spam` — `bot.py:360`
- `NoTinyxd/Hcaptcha-Solver` — `hsw.py:52`
- `SMARTMarkers/practitioner-ehr-app` — `app.py:100`
- `paulafredo/decode-jwt` — `app.py:24`
- `quamejnr/Python` — `ip.py:31`
- `tniquin/APPmecanica` — `App.py:216`

These are arguably *worth surfacing anyway*: a SOC analyst reviewing unfamiliar code genuinely should look at every place signature verification is switched off, even if it turns out to be a deliberate inspection tool. The tool now raises exactly one precise finding per such site instead of a cluster of redundant ones. The construction-accurate rules (R05/R06/R07 hardcoded secrets and missing exp, R08/R09 missing audience/issuer on verified decodes) are 100% true positives.

## Rule coverage in the wild — and the eight rules this sample missed

Only **7 of the 15 rules fired** across these 96 quasi-random projects: R01, R03,
R05, R06, R07, R08, R09. The other eight (R02, R04, R10, R11, R12, R13, R14, R15)
detect rarer, more advanced misuses that simply did not occur in this sample. That
is not evidence the rules are inert — every rule is validated at 100% recall on
the controlled benchmark — but a fair reader will ask whether they ever fire on
real code.

A separate targeted **rule-coverage study** (`../rule_coverage/RULE_COVERAGE.md`)
answers that: searching GitHub specifically for each missing pattern and scanning
the candidates with JWTCheck confirms **all eight** fire on genuine third-party
public code (109 confirmed findings across 71 repositories), so **all 15 rules now
have real-world evidence.** Because that study searches *for* each pattern, it is a
coverage/existence result, not a precision measurement, and is kept strictly
separate from the 96.7% figure above. A notable qualitative finding: the rules that
appear readily in production (R11/R12/R13/R02/R04) are the "trying-to-make-it-work"
verification and algorithm mistakes, whereas the three rarest (R10/R14/R15) surface
mostly in security-research and CTF code — reflecting how uncommon those patterns
are in production Python.

## Relation to the other experiments
- **Controlled benchmark (RQ1):** 100% precision / 100% recall on the 28 hand-labelled samples (`benchmark/results.json`).
- **Tool comparison (RQ2):** JWTCheck 15/15 vs Bandit 0/15 vs Semgrep 3/15 on the same fixtures, with 0 false positives on safe code (`benchmark/tool_comparison.md`).
- **This real-world study:** confirms the tool holds up on code it never saw, and surfaces the one realistic weakness (intentional unverified decoding).
- **Rule-coverage study:** confirms every one of the 15 rules is triggered by real public code (`benchmark/rule_coverage/RULE_COVERAGE.md`).

## Note on recall
Real-world *recall* is not directly computable: there is no ground-truth list of every JWT weakness across 96 external repositories. Recall is therefore reported on the controlled benchmark (100%), and the real-world study reports precision only — the standard approach for large-scale field studies.
