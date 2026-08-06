"""
portswigger_eval.py — RQ3: token-analyser detection across the PortSwigger
JWT lab vulnerability classes.

PortSwigger's "JWT" learning path has 8 labs. The web labs themselves require an
authenticated browser session to *solve* end-to-end; this harness instead
evaluates what the JWTCheck token analyser detects from a representative token
for each lab's vulnerability class. That is the part RQ3 actually claims: a SOC
analyst, given a captured token, gets an actionable cryptographic assessment
offline.

For each lab we build a representative token (stdlib only), run the analyser
(with brute-force where a weak key is the vector), and record whether the
analyser surfaced the lab's vulnerability class. Server-side-only flaws — where
the weakness is in how the *server* verifies, not in the token — are marked as
"server-side" and counted as not token-detectable, honestly.

Outputs benchmark/portswigger_results.md and .json.
Usage:  python benchmark/portswigger_eval.py
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from jwtcheck.analyser import Analyser  # noqa: E402
from jwtcheck.bruteforce import crack   # noqa: E402

WORDLIST = os.path.join(ROOT, "wordlists", "jwt-secrets.txt")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _token(header: dict, payload: dict, secret: str = None) -> str:
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    if secret is None:
        return f"{h}.{p}."          # unsigned (alg:none)
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


# Each lab: builder + the signal we expect the analyser to surface, and whether
# the class is token-detectable at all.
def _labs():
    return [
        {
            "lab": "1. Auth bypass via unverified signature",
            "token": _token({"alg": "HS256"}, {"sub": "admin"}, "secret"),
            "detect": lambda r: False,   # server-side: server simply doesn't verify
            "server_side": True,
            "vector": "Server does not verify the signature at all.",
        },
        {
            "lab": "2. Auth bypass via flawed signature verification (none)",
            "token": _token({"alg": "none"}, {"sub": "admin"}),
            "detect": lambda r: r.alg_severity == "CRITICAL",
            "server_side": False,
            "vector": "alg=none accepted.",
        },
        {
            "lab": "3. Auth bypass via weak signing key",
            "token": _token({"alg": "HS256"}, {"sub": "admin"}, "secret"),
            "detect": lambda r: r.cracked_secret is not None,
            "server_side": False,
            "vector": "HMAC secret recoverable from a wordlist.",
            "bruteforce": True,
        },
        {
            "lab": "4. JWK header injection",
            "token": _token(
                {"alg": "RS256", "jwk": {"kty": "RSA", "n": "AAA", "e": "AQAB"}},
                {"sub": "admin"}, "x"),
            "detect": lambda r: any(h.claim == "jwk" for h in r.header_findings),
            "server_side": False,
            "vector": "Attacker embeds a self-signed JWK in the header.",
        },
        {
            "lab": "5. JKU header injection",
            "token": _token(
                {"alg": "RS256", "jku": "https://attacker.example/jwks.json"},
                {"sub": "admin"}, "x"),
            "detect": lambda r: any(h.claim == "jku" for h in r.header_findings),
            "server_side": False,
            "vector": "Attacker points jku at a key they control.",
        },
        {
            "lab": "6. kid header path traversal",
            "token": _token(
                {"alg": "HS256", "kid": "../../../../dev/null"},
                {"sub": "admin"}, "x"),
            "detect": lambda r: any(h.claim == "kid" for h in r.header_findings),
            "server_side": False,
            "vector": "kid used in a path-traversal key lookup.",
        },
        {
            "lab": "7. Algorithm confusion (RS->HS)",
            "token": _token({"alg": "HS256"}, {"sub": "admin"}, "public-key-as-secret"),
            # Previously this was `lambda r: r.brute_force_candidate`, and the
            # row was scored as detected. That was wrong twice over: the
            # predicate is true of EVERY HS256 token, so it identifies the
            # algorithm family rather than the attack; and the row was
            # simultaneously marked server-side, i.e. not token-detectable.
            # A forged RS->HS token is bit-for-bit an ordinary HS256 token —
            # the confusion lives entirely in which key the server verifies
            # with, so no offline analyser can detect it from the token.
            "detect": lambda r: False,
            "server_side": True,
            "vector": "Server verifies an HMAC token with an RSA public key. "
                      "Indistinguishable from a legitimate HS256 token offline.",
        },
        {
            "lab": "8. kid header SQL injection",
            "token": _token(
                {"alg": "HS256", "kid": "x' UNION SELECT 'k"},
                {"sub": "admin"}, "x"),
            "detect": lambda r: any(h.claim == "kid" for h in r.header_findings),
            "server_side": False,
            "vector": "kid used unsafely in a SQL key lookup.",
        },
    ]


def main():
    analyser = Analyser()
    rows = []
    detected = 0

    for lab in _labs():
        report = analyser.analyse(lab["token"])
        if lab.get("bruteforce"):
            report.cracked_secret = crack(lab["token"], WORDLIST, timeout=10)
        ok = bool(lab["detect"](report))
        if ok:
            detected += 1
        rows.append({
            "lab": lab["lab"],
            "vector": lab["vector"],
            "server_side": lab["server_side"],
            "detected": ok,
            "summary_severity": report.summary_severity(),
        })

    n = len(rows)
    token_detectable = [r for r in rows if not r["server_side"]]
    td_hits = sum(1 for r in token_detectable if r["detected"])

    lines = [
        "# RQ3 — Token analyser vs PortSwigger JWT lab classes",
        "",
        "The analyser assesses a *captured token* offline. Server-side-only "
        "flaws (where the weakness is in the server's verification, not the "
        "token) are marked and excluded from the token-detectable denominator.",
        "",
        f"**Overall:** {detected}/{n} lab classes surfaced by the analyser.  ",
        f"**Token-detectable classes:** {td_hits}/{len(token_detectable)} detected.",
        "",
        "| Lab | Vector | Token-detectable | Detected | Severity |",
        "|-----|--------|------------------|----------|----------|",
    ]
    for r in rows:
        td = "no (server-side)" if r["server_side"] else "yes"
        det = "✅" if r["detected"] else "❌"
        lines.append(
            f"| {r['lab']} | {r['vector']} | {td} | {det} | {r['summary_severity']} |"
        )
    md = "\n".join(lines) + "\n"

    with open(os.path.join(HERE, "portswigger_results.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(HERE, "portswigger_results.json"), "w", encoding="utf-8") as fh:
        json.dump({"detected": detected, "n": n,
                   "token_detectable_hits": td_hits,
                   "token_detectable_total": len(token_detectable),
                   "rows": rows}, fh, indent=2)

    print("=" * 60)
    print("RQ3 — PortSwigger JWT lab classes")
    print("=" * 60)
    for r in rows:
        mark = "PASS" if r["detected"] else ("n/a " if r["server_side"] else "MISS")
        print(f"  [{mark}] {r['lab']}")
    print("-" * 60)
    print(f"Overall surfaced       : {detected}/{n}")
    print(f"Token-detectable hits  : {td_hits}/{len(token_detectable)}")
    print("\nWritten: benchmark/portswigger_results.md / .json")


if __name__ == "__main__":
    main()
