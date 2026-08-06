#!/usr/bin/env python3
"""
fetch_heldout.py — build a HELD-OUT validation set of PyJWT repositories.

Why this exists
---------------
The verification-disabled refinement (Chapter 5) was derived from an inspection
of the original 96 repositories and then measured on those same 96. That is a
resubstitution estimate, not an out-of-sample one. This script assembles a
fresh set the refinement has never seen, so the 96.7% figure can be checked
against code that played no part in producing it.

Selection
---------
The original study used GitHub *code* search for four PyJWT markers. Code
search requires authentication; if `gh` is logged in this script uses it and
the discovery channel matches the original exactly. Otherwise it falls back to
the unauthenticated *repository* search API and then applies the identical
predicate locally: a repository is kept only if its Python source actually
contains one of the same four markers.

The discovery channel therefore differs in the fallback path, but the
inclusion criterion — "contains a genuine PyJWT call site" — is the same, and
that is the criterion the precision claim depends on. State which path was
used when writing up.

Repositories already present in the original study are excluded, so the sets
are disjoint by construction.

Usage:
    python benchmark/fetch_heldout.py --target 30
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(ROOT, "heldout_targets")
MANIFEST = os.path.join(HERE, "heldout_repos.json")
ORIGINAL = os.path.join(HERE, "real_world_repos.txt")

# The same markers the original study selected on.
MARKERS = ("jwt.decode", "jwt.encode", "from jwt import", "PyJWKClient")

# Repository-search queries, used only when code search is unavailable.
REPO_QUERIES = [
    "pyjwt language:python",
    "jwt authentication language:python",
    "jwt flask language:python",
    "jwt fastapi language:python",
    "jwt django language:python",
    "json web token language:python",
    "jwt auth api language:python",
    "jwt token language:python",
]


def _api(url):
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "jwtcheck-heldout"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def load_original():
    """Repositories used in the original 96-repo study — must be excluded."""
    names = set()
    if os.path.exists(ORIGINAL):
        with open(ORIGINAL, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.add(line.lower())
    return names


def gh_code_search(limit):
    """Preferred path: replicate the original discovery channel exactly."""
    try:
        subprocess.run(["gh", "auth", "status"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None  # not authenticated — caller falls back

    found = []
    for marker in MARKERS:
        try:
            out = subprocess.run(
                ["gh", "search", "code", marker, "--language=python",
                 f"--limit={limit}", "--json", "repository"],
                capture_output=True, text=True, timeout=120, check=True,
            ).stdout
            for row in json.loads(out):
                name = row.get("repository", {}).get("nameWithOwner")
                if name:
                    found.append(name)
        except Exception as exc:                       # noqa: BLE001
            print(f"  [warn] code search '{marker}' failed: {exc}", file=sys.stderr)
    return found


def repo_search(per_query):
    """Fallback path: unauthenticated repository search."""
    found = []
    for q in REPO_QUERIES:
        url = ("https://api.github.com/search/repositories?q="
               + urllib.parse.quote(q)
               + f"&sort=updated&per_page={per_query}")
        try:
            data = _api(url)
            for item in data.get("items", []):
                if not item.get("fork"):
                    found.append(item["full_name"])
            print(f"  {q!r}: {len(data.get('items', []))} results")
        except urllib.error.HTTPError as exc:
            print(f"  [warn] {q!r} failed: {exc}", file=sys.stderr)
        time.sleep(7)   # unauthenticated search allows ~10 requests/minute
    return found


def is_the_library(path):
    """
    True if the repository IS PyJWT (a fork, port, or distro packaging of it)
    rather than an application that uses it.

    Repository search surfaces the library itself and its many forks, which
    must not enter the sample: the study measures misuse in application code,
    and PyJWT's own test suite constructs deliberately insecure tokens by
    design. The original study used code search for call sites, which did not
    have this problem; this filter restores the same effective sample.
    Detected by PyJWT's own package layout: a jwt/ directory containing
    api_jws.py and algorithms.py.
    """
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "venv", ".venv", "node_modules")]
        if os.path.basename(root) == "jwt" and {"api_jws.py", "algorithms.py"} <= set(files):
            return True
    return False


def uses_pyjwt(path):
    """Apply the original inclusion criterion to a cloned repository."""
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "venv", ".venv", "node_modules")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            try:
                with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if any(m in text for m in MARKERS):
                return True
    return False


def clone(name, dest):
    """Shallow-clone a repository. Returns the commit SHA, or None on failure."""
    url = f"https://github.com/{name}.git"
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, dest],
                       capture_output=True, timeout=180, check=True)
        sha = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return sha
    except Exception:                                   # noqa: BLE001
        shutil.rmtree(dest, ignore_errors=True)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=30,
                    help="How many qualifying repositories to keep (default 30).")
    ap.add_argument("--per-query", type=int, default=30)
    args = ap.parse_args()

    excluded = load_original()
    print(f"Excluding {len(excluded)} repositories from the original study.\n")

    print("Discovering candidates...")
    candidates = gh_code_search(args.per_query)
    channel = "gh code search (matches the original study exactly)"
    if candidates is None:
        print("  gh not authenticated — falling back to repository search.")
        print("  (run `gh auth login` for an exact replication of the original channel)\n")
        candidates = repo_search(args.per_query)
        channel = "unauthenticated repository search + local marker filter"

    # de-duplicate, preserve order, drop anything used in the original study
    seen, ordered = set(), []
    for name in candidates:
        key = name.lower()
        if key in excluded or key in seen:
            continue
        seen.add(key)
        ordered.append(name)

    print(f"\n{len(ordered)} unique candidates not in the original study.")
    os.makedirs(OUT_DIR, exist_ok=True)

    kept, rejected = [], 0
    for name in ordered:
        if len(kept) >= args.target:
            break
        dest = os.path.join(OUT_DIR, name.replace("/", "__"))
        if os.path.exists(dest):
            continue
        sha = clone(name, dest)
        if sha is None:
            continue
        if is_the_library(dest) or not uses_pyjwt(dest):
            shutil.rmtree(dest, ignore_errors=True)
            rejected += 1
            continue
        kept.append({"repo": name, "commit": sha,
                     "path": os.path.relpath(dest, ROOT).replace("\\", "/")})
        print(f"  [{len(kept):2}/{args.target}] {name}  @ {sha[:10]}")

    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump({
            "purpose": "held-out validation set for the Chapter 5 precision study",
            "discovery_channel": channel,
            "inclusion_criterion": f"repository contains one of {list(MARKERS)}",
            "excluded_from": "benchmark/real_world_repos.txt (the original 96)",
            "count": len(kept),
            "repos": kept,
        }, fh, indent=2)

    print(f"\nKept {len(kept)} repositories; rejected {rejected} with no PyJWT usage.")
    print(f"Cloned into : {OUT_DIR}")
    print(f"Manifest    : {MANIFEST}")
    print("\nScan them with:")
    print("  python -m jwtcheck.cli scan heldout_targets --exclude-tests")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (used in repo_search)
    main()
