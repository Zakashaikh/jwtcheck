"""
generate_fixtures.py — reproducibly materialise the test fixtures.

Creates:
  tests/fixtures/vulnerable/*.py   one file per rule R01–R15
  tests/fixtures/safe/*.py         files that must yield zero findings
  tests/fixtures/tokens/*.txt      real JWT tokens for analyser tests

Run:  python tests/generate_fixtures.py
"""

import base64
import hashlib
import hmac
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")


# ---------------------------------------------------------------------------
# Vulnerable fixtures — one per rule
# ---------------------------------------------------------------------------

VULNERABLE = {
    "r01_no_algorithms.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key)  # R01: no algorithms parameter\n',

    "r02_none_algorithm.py":
        'import jwt\n'
        'decoded = jwt.decode(token, "", algorithms=["none"])  # R02\n',

    "r03_verify_signature_false.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], '
        'audience="a", issuer="i", options={"verify_signature": False})  # R03\n',

    "r04_algorithm_confusion.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256", "RS256"], '
        'audience="a", issuer="i")  # R04\n',

    "r05_hardcoded_secret_encode.py":
        'import jwt\n'
        'token = jwt.encode({"sub": "u", "exp": 1700000000}, "mysecret", '
        'algorithm="HS256")  # R05\n',

    "r06_hardcoded_secret_decode.py":
        'import jwt\n'
        'decoded = jwt.decode(token, "mysecret", algorithms=["HS256"], '
        'audience="a", issuer="i")  # R06\n',

    "r07_no_exp_claim.py":
        'import jwt\n'
        'payload = {"sub": "user123", "name": "Alice"}  # no exp\n'
        'token = jwt.encode(payload, secret, algorithm="HS256")  # R07\n',

    "r08_no_audience.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], issuer="i")  # R08\n',

    "r09_no_issuer.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], audience="a")  # R09\n',

    "r10_excessive_lifetime.py":
        'import jwt\n'
        'payload = {"sub": "u", "iat": 1700000000, "exp": 1700200000}  # >24h apart\n'
        'token = jwt.encode(payload, secret, algorithm="HS256")  # R10\n',

    "r11_verify_iss_false.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], '
        'audience="a", issuer="i", options={"verify_iss": False})  # R11\n',

    "r12_excessive_leeway.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], '
        'audience="a", issuer="i", leeway=600)  # R12\n',

    "r13_verify_exp_false.py":
        'import jwt\n'
        'decoded = jwt.decode(token, key, algorithms=["HS256"], '
        'audience="a", issuer="i", options={"verify_exp": False})  # R13\n',

    "r14_rsa_string_key.py":
        'import jwt\n'
        'key = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\\n'
        '-----END PUBLIC KEY-----"\n'
        'decoded = jwt.decode(token, key, algorithms=["RS256"], '
        'audience="a", issuer="i")  # R14\n',

    "r15_env_secret_multi_alg.py":
        'import jwt\n'
        'import os\n'
        'secret = os.environ.get("JWT_SECRET")\n'
        'decoded = jwt.decode(token, secret, algorithms=["HS256", "RS256"], '
        'audience="a", issuer="i")  # R15\n',
}


# ---------------------------------------------------------------------------
# Safe fixtures — must yield zero findings
# ---------------------------------------------------------------------------

SAFE = {
    "correct_usage.py":
        'import jwt\n'
        'import os\n'
        'payload = {"sub": "user123", "exp": 1700000000, "iat": 1699913600, '
        '"aud": "myapp", "iss": "auth.myapp.com"}\n'
        'token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")\n'
        'decoded = jwt.decode(token, os.environ["JWT_SECRET"], '
        'algorithms=["HS256"], audience="myapp", issuer="auth.myapp.com")\n',

    "bytes_decode.py":
        'def to_text(data):\n'
        '    return data.decode("utf-8")  # not jwt.decode\n',

    "str_encode.py":
        'def to_bytes(text):\n'
        '    return text.encode("utf-8")  # not jwt.encode\n',

    "no_jwt.py":
        'import json\n'
        'def load(path):\n'
        '    with open(path) as f:\n'
        '        return json.load(f)\n',
}


# ---------------------------------------------------------------------------
# Token fixtures — real JWTs (built with stdlib only)
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


def _make_none(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}."


def _token_fixtures() -> dict:
    now = int(time.time())
    return {
        # HS256 signed with the weak secret "secret" — brute-force must crack it
        "hs256_weak_secret.txt":
            _make_hs256({"sub": "1234567890", "name": "John Doe",
                         "iat": now, "exp": now + 3600}, "secret"),
        # alg:none, no signature
        "none_algorithm.txt":
            _make_none({"sub": "admin", "role": "admin"}),
        # valid token with exp in the past
        "expired.txt":
            _make_hs256({"sub": "u", "iat": now - 7200, "exp": now - 3600}, "secret"),
        # valid token with no exp / aud / iss
        "missing_claims.txt":
            _make_hs256({"sub": "user123", "name": "Alice"}, "secret"),
    }


# ---------------------------------------------------------------------------
# Materialise
# ---------------------------------------------------------------------------

def main() -> None:
    for sub, mapping in (("vulnerable", VULNERABLE), ("safe", SAFE)):
        d = os.path.join(FIX, sub)
        os.makedirs(d, exist_ok=True)
        for name, code in mapping.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(code)

    tdir = os.path.join(FIX, "tokens")
    os.makedirs(tdir, exist_ok=True)
    for name, tok in _token_fixtures().items():
        with open(os.path.join(tdir, name), "w", encoding="utf-8") as fh:
            fh.write(tok + "\n")

    print(f"Fixtures written under {FIX}")
    print(f"  vulnerable: {len(VULNERABLE)} files")
    print(f"  safe:       {len(SAFE)} files")
    print(f"  tokens:     4 files")


if __name__ == "__main__":
    main()
