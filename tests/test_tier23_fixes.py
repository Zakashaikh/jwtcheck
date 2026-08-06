"""
test_tier23_fixes.py — regressions for defects found in the late audit.

Each test here pins a behaviour that was wrong before the audit, so that a
future change cannot quietly restore the old behaviour.
"""

import os
import tempfile

import pytest

from jwtcheck.bruteforce import CrackStatus, crack, crack_detailed
from jwtcheck.scanner import Scanner
from jwtcheck.utils import base64url_decode


def _scan(src: str):
    path = os.path.join(tempfile.mkdtemp(), "sample.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    return sorted(f.rule_id for f in Scanner().scan_file(path))


# --- base64url must be strict -------------------------------------------
# b64decode() without validate=True silently discards characters outside the
# alphabet, so a token no conformant verifier would accept still decoded.

@pytest.mark.parametrize("bad", ["eyJh*bGci", "eyJh#bGci", "eyJh bGci"])
def test_non_alphabet_characters_rejected(bad):
    with pytest.raises(ValueError):
        base64url_decode(bad)


@pytest.mark.parametrize("bad", ["ab+cd", "ab/cd"])
def test_base64_but_not_base64url_rejected(bad):
    # '+' and '/' are base64 but not base64url (RFC 4648 s5).
    with pytest.raises(ValueError):
        base64url_decode(bad)


def test_valid_base64url_still_decodes():
    assert base64url_decode("eyJhbGciOiJIUzI1NiJ9") == b'{"alg":"HS256"}'


# --- a public key is not a hardcoded secret ------------------------------

def test_pem_public_key_raises_r14_not_r06():
    ids = _scan(
        'import jwt\n'
        'key = "-----BEGIN PUBLIC KEY-----AAA"\n'
        'jwt.decode(t, key, algorithms=["RS256"], audience="a", issuer="i")\n'
    )
    assert "R14" in ids
    assert "R06" not in ids, "a public verification key is not a hardcoded secret"


def test_ordinary_string_secret_still_raises_r06():
    ids = _scan(
        'import jwt\n'
        'jwt.decode(t, "hunter2", algorithms=["HS256"], audience="a", issuer="i")\n'
    )
    assert "R06" in ids
    assert "R14" not in ids


# --- a negative brute-force result must be interpretable -----------------

def _wordlist(words):
    path = os.path.join(tempfile.mkdtemp(), "wl.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words))
    return path


def test_exhausted_is_distinguishable_from_timeout():
    import base64
    import hashlib
    import hmac
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    signing_input = f'{seg({"alg": "HS256"})}.{seg({"sub": "1"})}'
    sig = hmac.new(b"correct-horse", signing_input.encode(), hashlib.sha256).digest()
    token = signing_input + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    hit = crack_detailed(token, _wordlist(["a", "correct-horse", "b"]))
    assert hit.status is CrackStatus.CRACKED
    assert hit.secret == "correct-horse"

    miss = crack_detailed(token, _wordlist(["a", "b", "c"]))
    assert miss.status is CrackStatus.EXHAUSTED
    assert miss.secret is None
    # the whole point: exhaustion is not the same claim as a timeout
    assert miss.status is not CrackStatus.TIMEOUT


def test_non_hmac_token_reports_not_hmac():
    import base64
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    token = f'{seg({"alg": "RS256"})}.{seg({"sub": "1"})}.AAAA'
    assert crack_detailed(token, _wordlist(["a"])).status is CrackStatus.NOT_HMAC
    # the legacy wrapper still returns None for callers that only want a secret
    assert crack(token, _wordlist(["a"])) is None
