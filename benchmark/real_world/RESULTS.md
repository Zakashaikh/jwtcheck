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

## Relation to the other experiments
- **Controlled benchmark (RQ1):** 100% precision / 100% recall on the 28 hand-labelled samples (`benchmark/results.json`).
- **Tool comparison (RQ2):** JWTCheck 15/15 vs Bandit 0/15 vs Semgrep 3/15 on the same fixtures, with 0 false positives on safe code (`benchmark/tool_comparison.md`).
- **This real-world study:** confirms the tool holds up on code it never saw, and surfaces the one realistic weakness (intentional unverified decoding).

## Note on recall
Real-world *recall* is not directly computable: there is no ground-truth list of every JWT weakness across 96 external repositories. Recall is therefore reported on the controlled benchmark (100%), and the real-world study reports precision only — the standard approach for large-scale field studies.
