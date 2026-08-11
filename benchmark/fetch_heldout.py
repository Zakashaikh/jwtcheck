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

# Source patterns that make R03 (SignatureVerificationDisabled) fire. The first
# held-out sample contained none of them, so the verification-disabled
# refinement never activated and could not be validated. --require-r03
# stratifies a sample on this predicate so the refinement can be measured.
VERIFY_DISABLED_MARKERS = (
    '"verify_signature": False', "'verify_signature': False",
    '"verify_signature":False', "'verify_signature':False",
    "verify=False", "verify = False",
)

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
        # Older PyJWT releases ship api.py rather than api_jws.py, and src/
        # layouts nest the package, so match on algorithms.py plus any of the
        # API modules. The stricter two-file test let two forks through.
        if os.path.basename(root) == "jwt" and "algorithms.py" in files \
                and {"api_jws.py", "api_jwt.py", "api.py"} & set(files):
            return True
    return False


# Substring, not word-bounded: real package names run the token together
# ("djangorestframework-simplejwt", "pyjwt", "authlib", "authx").
LIB_NAME_RE = re.compile(r"(jwt|jose|oauth|oidc|openid|keycloak|authlib|authx)", re.I)
# Descriptions need a second signal, so an application that merely says it
# "uses JWT" is not mistaken for a library.
LIB_KIND_RE = re.compile(r"(librar|sdk|toolkit|middleware|plugin|framework|"
                         r"implementation of|client for)", re.I)
PACKAGING_FILES = ("pyproject.toml", "setup.py", "setup.cfg")


def is_jwt_library(path):
    """
    True if the repository ships as a JWT/auth library or tool.

    Stratifying on --require-r03 selects heavily for this population:
    libraries implement verification themselves, and token inspectors,
    vulnerability analysers and teaching labs disable it by design. They are
    out of scope for a study of misuse in *application* code, and including
    them biases precision badly — the first R03-stratified draw returned 23
    packaged projects out of 30.
    """
    for fn in PACKAGING_FILES:
        fp = os.path.join(path, fn)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                meta = fh.read()
        except OSError:
            continue
        # Only the descriptive fields, so a mere dependency on PyJWT does not
        # disqualify an ordinary application.
        names = re.findall(r"^\s*name\s*[=:]\s*(.+)$", meta, re.I | re.M)
        blurb = re.findall(r"^\s*(?:description|keywords|summary)\s*[=:]\s*(.+)$",
                           meta, re.I | re.M)
        if any(LIB_NAME_RE.search(n) for n in names):
            return True
        if any(LIB_NAME_RE.search(b) and LIB_KIND_RE.search(b) for b in blurb):
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


def disables_verification(path):
    """True if any Python file in the repository turns PyJWT verification off."""
    return _contains_any(path, VERIFY_DISABLED_MARKERS)


def _contains_any(path, needles):
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
            if any(m in text for m in needles):
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
    ap.add_argument("--out-dir", default=OUT_DIR,
                    help="Where to clone (default heldout_targets/).")
    ap.add_argument("--manifest", default=MANIFEST,
                    help="Manifest to write (default benchmark/heldout_repos.json).")
    ap.add_argument("--exclude-manifest", action="append", default=[],
                    help="Also exclude every repo in this manifest. Repeatable; "
                         "use it to keep a third sample disjoint from the second.")
    ap.add_argument("--require-r03", action="store_true",
                    help="Keep only repositories that disable signature "
                         "verification somewhere, so R03 actually fires.")
    ap.add_argument("--exclude-libraries", action="store_true",
                    help="Drop JWT/auth libraries and tools, keeping only "
                         "applications. Strongly recommended with "
                         "--require-r03, which otherwise selects for them.")
    args = ap.parse_args()

    out_dir, manifest_path = args.out_dir, args.manifest

    excluded = load_original()
    print(f"Excluding {len(excluded)} repositories from the original study.")
    for mf in args.exclude_manifest:
        with open(mf, encoding="utf-8") as fh:
            prior = json.load(fh)["repos"]
        excluded |= {e["repo"].lower() for e in prior}
        print(f"Excluding {len(prior)} more from {os.path.basename(mf)}.")
    if args.require_r03:
        print("Stratifying: only repositories that disable verification are kept.")
    print()

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

    print(f"\n{len(ordered)} unique candidates not already used.")
    os.makedirs(out_dir, exist_ok=True)

    kept, rejected, no_r03, libs = [], 0, 0, 0
    for name in ordered:
        if len(kept) >= args.target:
            break
        dest = os.path.join(out_dir, name.replace("/", "__"))
        if os.path.exists(dest):
            continue
        sha = clone(name, dest)
        if sha is None:
            continue
        if is_the_library(dest) or not uses_pyjwt(dest):
            shutil.rmtree(dest, ignore_errors=True)
            rejected += 1
            continue
        if args.exclude_libraries and is_jwt_library(dest):
            shutil.rmtree(dest, ignore_errors=True)
            libs += 1
            continue
        if args.require_r03 and not disables_verification(dest):
            shutil.rmtree(dest, ignore_errors=True)
            no_r03 += 1
            continue
        kept.append({"repo": name, "commit": sha,
                     "path": os.path.relpath(dest, ROOT).replace("\\", "/")})
        print(f"  [{len(kept):2}/{args.target}] {name}  @ {sha[:10]}")

    criterion = f"repository contains one of {list(MARKERS)}"
    if args.require_r03:
        criterion += (" AND disables signature verification somewhere "
                      f"(one of {list(VERIFY_DISABLED_MARKERS)})")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump({
            "purpose": ("R03-stratified validation set" if args.require_r03
                        else "held-out validation set for the Chapter 5 precision study"),
            "discovery_channel": channel,
            "inclusion_criterion": criterion,
            "excluded_from": ["benchmark/real_world_repos.txt (the original 96)"]
                             + args.exclude_manifest,
            "count": len(kept),
            "repos": kept,
        }, fh, indent=2)

    print(f"\nKept {len(kept)}; rejected {rejected} with no PyJWT usage"
          + (f"; {no_r03} had PyJWT but never disable verification" if args.require_r03 else "")
          + (f"; {libs} were JWT/auth libraries rather than applications" if args.exclude_libraries else "")
          + ".")
    print(f"Cloned into : {out_dir}")
    print(f"Manifest    : {manifest_path}")
    print("\nScan them with:")
    print(f"  python benchmark/run_real_world.py --manifest {manifest_path} --out benchmark/third")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (used in repo_search)
    main()
