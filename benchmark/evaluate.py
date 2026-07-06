"""
evaluate.py — score the JWTCheck scanner against the labelled benchmark.

For every sample in corpus_spec.py, the scanner is run and its reported rule IDs
are compared to the ground-truth `expected` set. Detection is evaluated at the
(sample, rule) level: for each of the 15 rules and each sample we record whether
the rule was expected and whether it fired, giving:

    TP — rule expected and fired
    FP — rule fired but not expected
    FN — rule expected but did not fire
    TN — rule not expected and did not fire

From these we report per-rule and overall precision, recall, and F1, plus a
sample-level summary (exact-match accuracy and false-positive count on safe
samples). Results are printed as a table and written to benchmark/results.json.

Usage:
    python benchmark/evaluate.py
"""

import json
import os
import sys
import tempfile

# Make the jwtcheck package importable when run from anywhere.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from corpus_spec import all_samples              # noqa: E402
from jwtcheck.rules import all_rules             # noqa: E402
from jwtcheck.scanner import Scanner             # noqa: E402

ALL_RULE_IDS = [r.id for r in all_rules()]


def _scan_code(scanner: Scanner, code: str) -> set:
    """Write code to a temp .py file, scan it, return the set of fired rule IDs."""
    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(code)
        return {f.rule_id for f in scanner.scan_file(path)}
    finally:
        os.unlink(path)


def _prf(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return precision, recall, f1


def main() -> int:
    scanner = Scanner()
    samples = all_samples()

    # Per-rule confusion counts
    counts = {rid: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rid in ALL_RULE_IDS}

    # Sample-level bookkeeping
    exact_matches = 0
    safe_false_positives = 0
    per_sample = []

    for sample in samples:
        fired = _scan_code(scanner, sample.code)
        expected = sample.expected

        for rid in ALL_RULE_IDS:
            exp = rid in expected
            got = rid in fired
            if exp and got:
                counts[rid]["tp"] += 1
            elif got and not exp:
                counts[rid]["fp"] += 1
            elif exp and not got:
                counts[rid]["fn"] += 1
            else:
                counts[rid]["tn"] += 1

        is_exact = (fired == expected)
        if is_exact:
            exact_matches += 1
        if sample.category == "safe" and fired:
            safe_false_positives += 1

        per_sample.append({
            "name": sample.name,
            "category": sample.category,
            "expected": sorted(expected),
            "fired": sorted(fired),
            "exact_match": is_exact,
        })

    # Aggregate (micro) over all rules
    TP = sum(c["tp"] for c in counts.values())
    FP = sum(c["fp"] for c in counts.values())
    FN = sum(c["fn"] for c in counts.values())
    micro_p, micro_r, micro_f1 = _prf(TP, FP, FN)

    # ----- Print report --------------------------------------------------
    print("=" * 70)
    print("JWTCheck — Benchmark Evaluation")
    print("=" * 70)
    print(f"Samples: {len(samples)} "
          f"({sum(1 for s in samples if s.category=='vulnerable')} vulnerable, "
          f"{sum(1 for s in samples if s.category=='safe')} safe)")
    print()
    print(f"{'Rule':<6}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Prec':>8}{'Rec':>8}{'F1':>8}")
    print("-" * 70)
    macro_p = macro_r = macro_f1 = 0.0
    scored_rules = 0
    for rid in ALL_RULE_IDS:
        c = counts[rid]
        # Only average over rules that appear in the corpus (tp+fn > 0)
        p, r, f1 = _prf(c["tp"], c["fp"], c["fn"])
        if (c["tp"] + c["fn"]) > 0:
            macro_p += p
            macro_r += r
            macro_f1 += f1
            scored_rules += 1
        print(f"{rid:<6}{c['tp']:>4}{c['fp']:>4}{c['fn']:>4}{c['tn']:>4}"
              f"{p:>8.2f}{r:>8.2f}{f1:>8.2f}")
    print("-" * 70)
    if scored_rules:
        macro_p /= scored_rules
        macro_r /= scored_rules
        macro_f1 /= scored_rules
    print(f"{'MICRO':<6}{TP:>4}{FP:>4}{FN:>4}{'':>4}"
          f"{micro_p:>8.2f}{micro_r:>8.2f}{micro_f1:>8.2f}")
    print(f"{'MACRO':<6}{'':>16}"
          f"{macro_p:>8.2f}{macro_r:>8.2f}{macro_f1:>8.2f}  "
          f"(over {scored_rules} exercised rules)")
    print()
    print(f"Sample exact-match accuracy : {exact_matches}/{len(samples)} "
          f"({100*exact_matches/len(samples):.1f}%)")
    print(f"False positives on safe code: {safe_false_positives} "
          f"/ {sum(1 for s in samples if s.category=='safe')} safe samples")
    print()

    # Surface any mismatches explicitly (useful while iterating)
    mismatches = [ps for ps in per_sample if not ps["exact_match"]]
    if mismatches:
        print("Mismatches (expected != fired):")
        for m in mismatches:
            missed = sorted(set(m["expected"]) - set(m["fired"]))
            extra = sorted(set(m["fired"]) - set(m["expected"]))
            print(f"  {m['name']:<26} missed={missed or '-'} extra={extra or '-'}")
    else:
        print("All samples matched ground truth exactly.")

    # ----- Persist results -----------------------------------------------
    results = {
        "n_samples": len(samples),
        "micro": {"precision": micro_p, "recall": micro_r, "f1": micro_f1,
                  "tp": TP, "fp": FP, "fn": FN},
        "macro": {"precision": macro_p, "recall": macro_r, "f1": macro_f1,
                  "scored_rules": scored_rules},
        "exact_match_accuracy": exact_matches / len(samples),
        "safe_false_positives": safe_false_positives,
        "per_rule": counts,
        "per_sample": per_sample,
    }
    out_path = os.path.join(HERE, "results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nResults written to {out_path}")

    # Non-zero exit if the tool is not perfect, so this can gate CI if desired.
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
