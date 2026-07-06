"""
test_bruteforce.py — HMAC secret recovery tests.

Tokens are generated with stdlib hmac/hashlib so these tests need no PyJWT.
"""

import base64
import hashlib
import hmac
import inspect
import json
import os
import tempfile

import pytest

from jwtcheck import bruteforce
from jwtcheck.bruteforce import crack


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(secret: str, alg: str = "HS256") -> str:
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}[alg]
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": "user"}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64(hmac.new(secret.encode(), signing_input, hash_fn).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture()
def wordlist(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("wrong1\nwrong2\nsecret\npassword\n", encoding="utf-8")
    return str(path)


def test_uses_compare_digest_not_equals():
    """Academic requirement: constant-time comparison must be used."""
    src = inspect.getsource(bruteforce)
    assert "compare_digest" in src


def test_crack_hs256(wordlist):
    token = _make_token("secret", "HS256")
    assert crack(token, wordlist, timeout=10) == "secret"


def test_crack_hs384(wordlist):
    token = _make_token("password", "HS384")
    assert crack(token, wordlist, timeout=10) == "password"


def test_crack_hs512(wordlist):
    token = _make_token("password", "HS512")
    assert crack(token, wordlist, timeout=10) == "password"


def test_secret_not_in_wordlist_returns_none(wordlist):
    token = _make_token("notinlist", "HS256")
    assert crack(token, wordlist, timeout=10) is None


def test_non_hmac_algorithm_returns_none(wordlist):
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": "u"}).encode())
    token = f"{header}.{payload}.{_b64(b'sig')}"
    assert crack(token, wordlist, timeout=5) is None


def test_malformed_token_raises_value_error(wordlist):
    with pytest.raises(ValueError):
        crack("only.two", wordlist)
