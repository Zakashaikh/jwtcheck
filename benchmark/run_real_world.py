"""
run_real_world.py — clone and scan the sampled real-world repositories.

Reads benchmark/real_world_repos.txt (produced by fetch_targets.py), shallow-
clones each repository into realworld_targets/, runs the JWTCheck scanner over
each, and writes:

    benchmark/real_world/summary.json    per-repo finding counts + rule tallies
    benchmark/real_world/summary.md      human-readable table
    benchmark/real_world/triage.md       one row per finding, with a blank
                                         TP/FP column for you to fill in manually

The triage step (deciding TP vs FP for each finding) is what produces the
real-world precision figure for the dissertation; this script lays out the
findings so that judgement is all that remains.

Usage:
    python benchmark/run_real_world.py            # clone (if needed) + scan
    python benchmark/run_real_world.py --no-clone # scan already-cloned repos
Requires: git on PATH.
"""

import argparse
import collections
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from jwtcheck.scanner import Scanner  # noqa: E402

REPO_LIST = os.path.join(HERE, "real_world_repos.txt")
TARGETS_DIR = os.path.join(ROOT, "realworld_targets")
OUT_DIR = os.path.join(HERE, "real_world")


def read_repo_list(path=REPO_LIST):
    repos = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                repos.append(line)
    return repos


def clone(repo: str) -> str:
    """Shallow-clone repo into TARGETS_DIR; return local path or '' on failure."""
    safe = repo.replace("/", "__")
    dest = os.path.join(TARGETS_DIR, safe)
    if os.path.isdir(dest):
        return dest
    url = f"https://github.com/{repo}.git"
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            print(f"  [skip] {repo}: clone failed", file=sys.stderr)
            return ""
        return dest
    except subprocess.SubprocessError:
        print(f"  [skip] {repo}: clone timed out", file=sys.stderr)
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-clone", action="store_true",
                    help="Scan already-cloned repos without cloning.")
    ap.add_argument("--limit", type=int, default=0,
                    help="Only process the first N repos (0 = all).")
    ap.add_argument("--manifest",
                    help="JSON manifest (e.g. heldout_repos.json) instead of "
                         "the .txt list. Entries carry their own commit-pinned "
                         "local path, so nothing is cloned or re-resolved.")
    ap.add_argument("--out", help=f"Output directory (default: {OUT_DIR}).")
    args = ap.parse_args()

    out_dir = args.out or OUT_DIR
    label = "Held-out" if args.manifest else "Real-world"

    os.makedirs(TARGETS_DIR, exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)

    if args.manifest:
        with open(args.manifest, encoding="utf-8") as fh:
            entries = json.load(fh)["repos"]
        repos = [e["repo"] for e in entries]
        known_paths = {e["repo"]: os.path.join(ROOT, e["path"]) for e in entries}
    else:
        repos = read_repo_list()
        known_paths = {}
    if args.limit:
        repos = repos[:args.limit]

    scanner = Scanner()
    per_repo = []
    rule_totals = collections.Counter()
    sev_totals = collections.Counter()
    triage_rows = []
    cloned_ok = 0

    for i, repo in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] {repo}")
        path = known_paths.get(repo) or (
            clone(repo) if not args.no_clone else os.path.join(
                TARGETS_DIR, repo.replace("/", "__")))
        if not path or not os.path.isdir(path):
            continue
        cloned_ok += 1

        findings = scanner.scan_directory(path, recursive=True, exclude_tests=True)
        by_rule = collections.Counter(f.rule_id for f in findings)
        by_sev = collections.Counter(f.severity for f in findings)
        rule_totals.update(by_rule)
        sev_totals.update(by_sev)

        per_repo.append({
            "repo": repo,
            "n_findings": len(findings),
            "by_rule": dict(by_rule),
            "by_severity": dict(by_sev),
        })
        for f in findings:
            rel = os.path.relpath(f.filepath, path)
            triage_rows.append({
                "repo": repo, "rule": f.rule_id, "severity": f.severity,
                "file": rel, "line": f.line, "snippet": f.snippet,
            })

    # ----- write summary.json -------------------------------------------
    summary = {
        "n_repos_listed": len(repos),
        "n_repos_scanned": cloned_ok,
        "total_findings": sum(p["n_findings"] for p in per_repo),
        "by_rule": dict(rule_totals),
        "by_severity": dict(sev_totals),
        "per_repo": per_repo,
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    # ----- write summary.md ---------------------------------------------
    lines = [
        f"# {label} scan summary",
        "",
        f"Repositories scanned: **{cloned_ok}/{len(repos)}**  ",
        f"Total findings: **{summary['total_findings']}**",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        lines.append(f"| {sev} | {sev_totals.get(sev, 0)} |")
    lines += ["", "## Findings by rule", "", "| Rule | Count |", "|------|-------|"]
    for rule in sorted(rule_totals):
        lines.append(f"| {rule} | {rule_totals[rule]} |")
    lines += ["", "## Repositories with the most findings", "",
              "| Repo | Findings |", "|------|----------|"]
    for p in sorted(per_repo, key=lambda x: -x["n_findings"])[:20]:
        lines.append(f"| {p['repo']} | {p['n_findings']} |")
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # ----- write triage.md (manual TP/FP classification) ----------------
    tlines = [
        f"# {label} triage worksheet",
        "",
        "Mark each finding TP (true positive) or FP (false positive) in the "
        f"last column. {label} precision = TP / (TP + FP).",
        "",
        "| Repo | Rule | Sev | File:Line | Snippet | TP/FP |",
        "|------|------|-----|-----------|---------|-------|",
    ]
    for r in triage_rows:
        snip = (r["snippet"] or "").replace("|", "\\|")[:70]
        tlines.append(
            f"| {r['repo']} | {r['rule']} | {r['severity']} | "
            f"{r['file']}:{r['line']} | `{snip}` |  |"
        )
    with open(os.path.join(out_dir, "triage.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(tlines) + "\n")

    print("\n" + "=" * 60)
    print(f"Scanned {cloned_ok}/{len(repos)} repos | "
          f"{summary['total_findings']} findings "
          f"(CRITICAL {sev_totals.get('CRITICAL',0)}, "
          f"HIGH {sev_totals.get('HIGH',0)}, "
          f"MEDIUM {sev_totals.get('MEDIUM',0)})")
    print(f"Reports in {out_dir}\\  (summary.json, summary.md, triage.md)")


if __name__ == "__main__":
    main()
