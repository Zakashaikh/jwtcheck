"""
find_rule_examples.py — targeted real-world coverage study for JWTCheck.

For each rule that did NOT fire in the primary 96-repo study (R02, R04, R10,
R11, R12, R13, R14, R15), search GitHub for candidate Python files, download
each via the contents API, and confirm with JWTCheck's own scanner that the
rule actually fires. Only confirmed hits are kept; the author's own repository
is excluded.

This is a coverage/existence study, NOT a precision measurement: candidates are
found by searching for the very pattern each rule detects, which biases the
sample toward positives by construction. See RULE_COVERAGE.md.

Requirements: an authenticated GitHub CLI (`gh auth status`).
Note: GitHub code search is rate-limited to ~10 requests/minute; the queries
below are grouped so a full run stays within a few minutes.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from jwtcheck.scanner import Scanner

SELF_REPO = "Zakashaikh/jwtcheck"
TARGET_RULES = {"R02", "R04", "R10", "R11", "R12", "R13", "R14", "R15"}

# (rule, [query terms]) — terms are ANDed by GitHub code search.
# Leading-dash phrases (PEM headers) are searched without the dashes because
# the CLI treats a leading '-' as a flag; the token still matches.
QUERIES = [
    ("R02", ['algorithms=["none"]']),
    ("R02", ["algorithms=['none']"]),
    ("R04", ["HS256", "RS256", "jwt.decode"]),
    ("R10", ["jwt.encode", '"exp": 99999']),
    ("R10", ["jwt.encode", "iat", "exp", "9999999999"]),
    ("R11", ["verify_iss", "jwt.decode"]),
    ("R12", ["leeway=3600"]),
    ("R12", ["leeway=600"]),
    ("R13", ["verify_exp", "jwt.decode"]),
    ("R14", ["BEGIN PUBLIC KEY-----", "jwt.decode", "algorithms"]),
    ("R14", ["public_key", "BEGIN PUBLIC KEY", "jwt.decode"]),
    ("R15", ["os.environ.get", 'algorithms=["HS256", "RS256"]']),
    ("R15", ["os.environ[", "algorithms=[", "jwt.decode"]),
]


def search(terms):
    """Return list of (repo, path) for a code-search query."""
    cmd = ["gh", "search", "code", *terms, "--language", "python",
           "--limit", "20", "--json", "repository,path",
           "--jq", ".[] | .repository.nameWithOwner + \"\\t\" + .path"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    rows = []
    for line in out.stdout.splitlines():
        if "\t" in line:
            repo, path = line.split("\t", 1)
            rows.append((repo, path))
    return rows


def fetch(repo, path):
    """Return decoded bytes of a file via the contents API, or None."""
    out = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/{path}", "--jq", ".content"],
        capture_output=True, text=True, timeout=30,
    )
    if out.returncode != 0 or not out.stdout.strip():
        return None
    try:
        return base64.b64decode(out.stdout.strip())
    except Exception:
        return None


def main():
    # 1. Gather unique candidate files.
    candidates = {}
    for rule, terms in QUERIES:
        for repo, path in search(terms):
            candidates.setdefault((repo, path), set()).add(rule)
    print(f"{len(candidates)} unique candidate files")

    # 2. Download + scan; keep confirmed target-rule hits.
    scanner = Scanner()
    confirmed = defaultdict(dict)  # rule -> {(repo,path,line): snippet}
    for (repo, path) in candidates:
        if repo == SELF_REPO:
            continue
        content = fetch(repo, path)
        if content is None:
            continue
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as tf:
            tf.write(content)
            tmp = tf.name
        try:
            findings = scanner.scan_file(tmp)
        finally:
            os.unlink(tmp)
        for f in findings:
            if f.rule_id in TARGET_RULES:
                confirmed[f.rule_id][(repo, path, f.line)] = f.snippet

    # 3. Report.
    out = {}
    for rule in sorted(TARGET_RULES):
        rows = confirmed.get(rule, {})
        repos = sorted({k[0] for k in rows})
        out[rule] = {
            "findings": len(rows),
            "repos": repos,
            "examples": [{"repo": k[0], "path": k[1], "line": k[2], "snippet": v}
                         for k, v in rows.items()],
        }
        print(f"{rule}: {len(rows):3d} finding(s) / {len(repos):2d} repo(s)")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "coverage_hits.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("wrote coverage_hits.json")


if __name__ == "__main__":
    main()
