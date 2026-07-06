"""
generate_corpus.py — materialise the labelled corpus to disk.

Writes each Sample from corpus_spec.py to benchmark/samples/<category>/<name>.py
and a ground-truth manifest (benchmark/ground_truth.json). Run once; the files
are browsable evidence for the methodology chapter and re-generable on demand.

Usage:
    python benchmark/generate_corpus.py
"""

import json
import os

from corpus_spec import all_samples

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(HERE, "samples")
MANIFEST = os.path.join(HERE, "ground_truth.json")


def main() -> None:
    manifest = {}
    for sample in all_samples():
        cat_dir = os.path.join(SAMPLES_DIR, sample.category)
        os.makedirs(cat_dir, exist_ok=True)
        path = os.path.join(cat_dir, f"{sample.name}.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# CORPUS SAMPLE: {sample.name}\n")
            fh.write(f"# CATEGORY: {sample.category}\n")
            fh.write(f"# EXPECTED RULES: {sorted(sample.expected) or 'NONE'}\n")
            fh.write(f"# NOTE: {sample.note}\n\n")
            fh.write(sample.code)
        rel = os.path.relpath(path, HERE).replace("\\", "/")
        manifest[rel] = {
            "category": sample.category,
            "expected": sorted(sample.expected),
            "note": sample.note,
        }

    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    total = len(manifest)
    vuln = sum(1 for v in manifest.values() if v["category"] == "vulnerable")
    safe = total - vuln
    print(f"Wrote {total} samples ({vuln} vulnerable, {safe} safe) to {SAMPLES_DIR}")
    print(f"Ground truth: {MANIFEST}")


if __name__ == "__main__":
    main()
