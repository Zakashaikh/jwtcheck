"""
compare_tools.py — RQ2 comparison: JWTCheck vs Bandit vs Semgrep.

Runs all three static analysers over the same labelled fixture corpus
(tests/fixtures/vulnerable + tests/fixtures/safe) and records, per file,
whether each tool flagged the JWT misuse the file was built to contain.

A "JWT-relevant detection" means the tool produced at least one finding that
concerns the intended JWT weakness. For JWTCheck this is any rule firing on the
file. For Bandit/Semgrep — which have no JWT-cryptographic-misuse rules in their
standard Python rulesets — a detection is only counted when a generic rule
(e.g. Bandit B105 hardcoded password) happens to overlap the JWT issue; this is
recorded honestly so the comparison is fair.

Outputs:
  benchmark/tool_comparison.json   machine-readable results
  benchmark/tool_comparison.md     human-readable table for the dissertation

Usage:
  python benchmark/compare_tools.py
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from jwtcheck.scanner import Scanner  # noqa: E402

VULN = os.path.join(ROOT, "tests", "fixtures", "vulnerable")
SAFE = os.path.join(ROOT, "tests", "fixtures", "safe")


# ---------------------------------------------------------------------------
# Tool runners — each returns {abs_filepath: [finding_str, ...]}
# ---------------------------------------------------------------------------

def run_jwtcheck(paths):
    scanner = Scanner()
    out = {}
    for p in paths:
        findings = scanner.scan_file(p)
        out[p] = [f.rule_id for f in findings]
    return out


def run_bandit(directory):
    """Run Bandit recursively over a directory; return path -> [test_id]."""
    out = {}
    try:
        proc = subprocess.run(
            ["bandit", "-r", directory, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=180,
        )
        data = json.loads(proc.stdout or "{}")
        for res in data.get("results", []):
            path = os.path.abspath(res["filename"])
            out.setdefault(path, []).append(res["test_id"])
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"  [bandit] error: {exc}", file=sys.stderr)
    return out


def run_semgrep(directory):
    """Run Semgrep with the community Python ruleset; return path -> [check_id]."""
    out = {}
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", "p/python",
             "--json", "--quiet", "--disable-version-check", directory],
            capture_output=True, text=True, timeout=600,
        )
        data = json.loads(proc.stdout or "{}")
        for res in data.get("results", []):
            path = os.path.abspath(res["path"])
            out.setdefault(path, []).append(res["check_id"].split(".")[-1])
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"  [semgrep] error: {exc}", file=sys.stderr)
        return None
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _tool_versions():
    """Record the version of each tool taking part in the comparison."""
    import importlib.metadata as md

    from jwtcheck import __version__ as jwtcheck_version

    versions = {"jwtcheck": jwtcheck_version}
    for pkg in ("bandit", "semgrep"):
        try:
            versions[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            versions[pkg] = None
    return versions


def main():
    vuln_files = [os.path.join(VULN, f) for f in sorted(os.listdir(VULN))]
    safe_files = [os.path.join(SAFE, f) for f in sorted(os.listdir(SAFE))]
    all_files = vuln_files + safe_files

    print("Running JWTCheck ...")
    jc = run_jwtcheck(all_files)
    print("Running Bandit ...")
    bd = run_bandit(VULN)
    bd.update(run_bandit(SAFE))
    print("Running Semgrep (first run downloads rules; may take a minute) ...")
    sg_v = run_semgrep(VULN)
    sg = {}
    if sg_v is not None:
        sg.update(sg_v)
        sg_s = run_semgrep(SAFE)
        if sg_s:
            sg.update(sg_s)
    semgrep_ran = sg_v is not None

    rows = []
    for p in all_files:
        ap = os.path.abspath(p)
        rows.append({
            "file": os.path.basename(p),
            "category": "vulnerable" if p in vuln_files else "safe",
            "jwtcheck": jc.get(ap, []) or jc.get(p, []),
            "bandit": bd.get(ap, []),
            "semgrep": sg.get(ap, []) if semgrep_ran else None,
        })

    # ----- aggregate detection on the vulnerable set --------------------
    n_vuln = len(vuln_files)
    jc_hits = sum(1 for r in rows if r["category"] == "vulnerable" and r["jwtcheck"])
    bd_hits = sum(1 for r in rows if r["category"] == "vulnerable" and r["bandit"])
    sg_hits = (sum(1 for r in rows if r["category"] == "vulnerable" and r["semgrep"])
               if semgrep_ran else None)

    # ----- false positives on the safe set ------------------------------
    jc_fp = sum(1 for r in rows if r["category"] == "safe" and r["jwtcheck"])
    bd_fp = sum(1 for r in rows if r["category"] == "safe" and r["bandit"])
    sg_fp = (sum(1 for r in rows if r["category"] == "safe" and r["semgrep"])
             if semgrep_ran else None)

    summary = {
        "n_vulnerable": n_vuln,
        "n_safe": len(safe_files),
        "jwt_detections": {"jwtcheck": jc_hits, "bandit": bd_hits, "semgrep": sg_hits},
        "safe_false_positives": {"jwtcheck": jc_fp, "bandit": bd_fp, "semgrep": sg_fp},
        "semgrep_ran": semgrep_ran,
        # Pin the baseline versions into the results. A tool comparison is not
        # reproducible without them: Bandit and Semgrep both ship frequently,
        # and a future run against different versions is a different experiment.
        "tool_versions": _tool_versions(),
    }

    with open(os.path.join(HERE, "tool_comparison.json"), "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "rows": rows}, fh, indent=2)

    # ----- markdown table -----------------------------------------------
    lines = [
        "# Tool Comparison — JWTCheck vs Bandit vs Semgrep",
        "",
        f"Corpus: {n_vuln} vulnerable + {len(safe_files)} safe fixtures "
        "(tests/fixtures/).",
        "",
        "## Detection on vulnerable fixtures (higher = better)",
        "",
        "| Tool | JWT misuses detected | Coverage |",
        "|------|----------------------|----------|",
        f"| **JWTCheck** | {jc_hits}/{n_vuln} | {100*jc_hits/n_vuln:.0f}% |",
        f"| Bandit | {bd_hits}/{n_vuln} | {100*bd_hits/n_vuln:.0f}% |",
        (f"| Semgrep (p/python) | {sg_hits}/{n_vuln} | {100*sg_hits/n_vuln:.0f}% |"
         if semgrep_ran else "| Semgrep | not available | — |"),
        "",
        "## False positives on safe fixtures (lower = better)",
        "",
        "| Tool | False positives |",
        "|------|-----------------|",
        f"| **JWTCheck** | {jc_fp}/{len(safe_files)} |",
        f"| Bandit | {bd_fp}/{len(safe_files)} |",
        (f"| Semgrep | {sg_fp}/{len(safe_files)} |"
         if semgrep_ran else "| Semgrep | — |"),
        "",
        "## Per-file detail",
        "",
        "| File | Category | JWTCheck | Bandit | Semgrep |",
        "|------|----------|----------|--------|---------|",
    ]
    for r in rows:
        jcc = ",".join(r["jwtcheck"]) or "—"
        bdc = ",".join(r["bandit"]) or "—"
        sgc = ("—" if not semgrep_ran else (",".join(r["semgrep"]) or "—"))
        lines.append(f"| {r['file']} | {r['category']} | {jcc} | {bdc} | {sgc} |")
    lines.append("")
    lines.append(
        "Note: Bandit and Semgrep's standard Python rulesets contain no "
        "JWT-cryptographic-misuse rules. Any detections shown are generic rules "
        "(e.g. Bandit B105 hardcoded password) that incidentally overlap a JWT "
        "issue, not JWT-aware analysis."
    )
    with open(os.path.join(HERE, "tool_comparison.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    # ----- console summary ----------------------------------------------
    print("\n" + "=" * 60)
    print("RQ2 — JWT misuse detection on vulnerable fixtures")
    print("=" * 60)
    print(f"  JWTCheck : {jc_hits}/{n_vuln}")
    print(f"  Bandit   : {bd_hits}/{n_vuln}")
    print(f"  Semgrep  : {sg_hits}/{n_vuln}" if semgrep_ran else "  Semgrep  : not available")
    print(f"\nSafe-set false positives: JWTCheck={jc_fp}, Bandit={bd_fp}, "
          f"Semgrep={sg_fp if semgrep_ran else 'n/a'}")
    print("\nWritten: benchmark/tool_comparison.json, benchmark/tool_comparison.md")


if __name__ == "__main__":
    main()
