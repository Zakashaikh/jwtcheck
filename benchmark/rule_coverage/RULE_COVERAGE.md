# Real-world rule-coverage study — all 15 rules exercised in the wild

The primary real-world study (`../real_world/RESULTS.md`) scanned 96 quasi-random
GitHub projects. Only **7 of the 15 rules** fired there: the common misuses
(R01, R05–R09) and the intentional-unverified-decode signal (R03). The other
eight rules cover rarer, more advanced misuses that simply did not occur in that
sample.

This follow-up study answers a narrower question: **does each of those eight
rules fire on real, third-party public code at all?** It is a *coverage /
existence* study, deliberately kept separate from the precision study.

> **Important — this is not a precision measurement.** Unlike the 96-repo study,
> here the repositories were *found by searching for the pattern each rule
> detects*. That biases the sample toward positives by construction, so no
> precision/recall figure is computed or claimed from it. The only claim is:
> each rule is triggered by genuine public code, with concrete citations.

## Method

1. For each of the eight previously-unseen rules, GitHub's code-search API was
   queried for source likely to contain the pattern (queries listed in
   [`find_rule_examples.py`](find_rule_examples.py)).
2. Every candidate file was downloaded via the GitHub contents API and scanned
   with JWTCheck itself — a keyword match alone was **not** counted; the rule had
   to actually fire under AST analysis.
3. Findings in the author's own repository (`Zakashaikh/jwtcheck`) were excluded.
4. Confirmed hits (repo, path, line, source line) are recorded in
   [`coverage_hits.json`](coverage_hits.json).

Access date: 2026-07-06 (default branch of each repository at that time).

**JWTCheck confirms, it does not find.** Step 1 is ordinary text search and returns
many candidates that do *not* trigger any rule; the tool's own AST analysis in step
2 is what validates each hit. The finding mechanism (GitHub code search) and the
confirming mechanism (JWTCheck) are deliberately different, so the tool is never
used to search for its own evidence.

### Evidence — every hit is pinned and reproducible

Each confirmed file was re-downloaded, **pinned to the exact commit SHA**, and
re-scanned (all 78 re-confirmed their rule on re-download):

- [`evidence_manifest.md`](evidence_manifest.md) — clickable, commit-pinned GitHub
  permalinks for every hit, grouped by rule. These are immutable: they keep
  pointing at the exact reviewed content even if a repo is later changed or deleted.
- [`evidence_manifest.json`](evidence_manifest.json) — the same, machine-readable,
  with commit SHA, blob SHA, line numbers, and the local archive path.
- The raw source files are kept in a local `evidence_archive/` (gitignored — it is
  third-party code under mixed licences, so it is not redistributed here).

## Result — 8 / 8 rules confirmed

All eight rules that were absent from the 96-repo study are exercised by real
public code. Combined with the seven rules seen there, **all 15 rules now have
real-world evidence.**

| Rule | Detects | Findings | Distinct repos | Representative real project |
|------|---------|:-------:|:-------:|-----------------------------|
| R02 | `none` algorithm accepted | 23 | 18 | `vincentwolsink/home_assistant_micronova_agua_iot` |
| R04 | Algorithm confusion (HMAC + asymmetric) | 28 | 21 | `fanout/pygripcontrol` (`algorithms=["HS256","RS256","ES256"]`) |
| R10 | Excessive token lifetime | 11 | 6 | `sstrntu/turfmapp-ai-agent` |
| R11 | Issuer verification disabled (`verify_iss=False`) | 11 | 9 | `dataloop-ai/dtlpy`, `NVIDIA-NeMo/nemo-platform` |
| R12 | Excessive `leeway` (> 300 s) | 7 | 6 | `maxdiegoduron/Measurement-Hub` (`leeway=3600`) |
| R13 | Expiry verification disabled (`verify_exp=False`) | 24 | 17 | `kujirashark/user_restful_api` |
| R14 | PEM key passed as a string literal | 3 | 3 | `Matthew1471/Enphase-API` |
| R15 | Env secret with algorithms not pinned | 2 | 2 | `hieudzpro2k10-svg/Pentest-API` |
| **Total** | | **109** | **71** | |

(The seven rules already validated in the wild: R01, R03, R05, R06, R07, R08, R09.)

## Honest reading of the results

- **Frequency tracks severity of intent, not severity of impact.** The rules that
  fire readily in ordinary production code — R11, R12, R13, R02, R04 — are
  disabled-verification and algorithm-selection mistakes that developers make
  while *trying* to get JWTs working. Several hits are in mature projects
  (an NVIDIA platform package, the Dataloop SDK, a Home Assistant integration,
  the Enphase API client).
- **The three rarest rules lean on security-research code.** R10, R14 and R15
  were hardest to find and their hits skew toward CTF archives, fuzzer corpora
  and deliberately-vulnerable pentest servers. That is itself a finding: hard-
  coding an epoch expiry (R10), inlining a PEM public key (R14), or loading a
  secret from the environment while leaving the algorithm list unpinned (R15)
  are genuinely uncommon in production Python — which is *why* they were absent
  from the random 96-repo sample.
- **Confirmed pattern, not triaged intent.** As in the R03 discussion, a
  `verify_exp=False` or a disabled check may be deliberate in context (a test, a
  token-inspection tool). These hits confirm the rule *matches real code*; they
  are not asserted to be exploitable weaknesses in every case.

## Reproduce

```bash
python benchmark/rule_coverage/find_rule_examples.py     # re-runs the search + scan
```

Requires an authenticated GitHub CLI (`gh auth status`) for the search and
contents APIs.
