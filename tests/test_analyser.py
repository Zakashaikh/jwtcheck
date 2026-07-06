"""
test_analyser.py — token assessment tests.

Real tokens are generated with PyJWT; all such tests are skipped when PyJWT is
not installed. Malformed-input tests need no dependency.
"""

import time

import pytest

from jwtcheck.analyser import Analyser

try:
    import jwt as _pyjwt
    PYJWT_AVAILABLE = True
except ImportError:
    PYJWT_AVAILABLE = False

_SECRET = "test-secret"
_analyser = Analyser()


def _make(payload: dict, alg: str = "HS256") -> str:
    return _pyjwt.encode(payload, _SECRET, algorithm=alg)


def _claim_names(report) -> set:
    return {cf.claim for cf in report.claim_findings}


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_expired_token_detected():
    token = _make({"sub": "u", "exp": int(time.time()) - 3600})
    report = _analyser.analyse(token)
    assert report.is_expired is True


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_no_exp_claim_flagged():
    token = _make({"sub": "u"})
    report = _analyser.analyse(token)
    assert "exp" in _claim_names(report)


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_missing_aud_flagged():
    token = _make({"sub": "u", "exp": int(time.time()) + 3600})
    report = _analyser.analyse(token)
    assert "aud" in _claim_names(report)


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_hs256_is_brute_force_candidate():
    token = _make({"sub": "u", "exp": int(time.time()) + 3600})
    report = _analyser.analyse(token)
    assert report.brute_force_candidate is True


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_algorithm_extracted_correctly():
    token = _make({"sub": "u", "exp": int(time.time()) + 3600})
    report = _analyser.analyse(token)
    assert report.algorithm == "HS256"


@pytest.mark.skipif(not PYJWT_AVAILABLE, reason="PyJWT not installed")
def test_future_iat_flagged():
    token = _make({"sub": "u", "iat": int(time.time()) + 9999, "exp": int(time.time()) + 99999})
    report = _analyser.analyse(token)
    assert "iat" in _claim_names(report)


def test_malformed_token_returns_error():
    report = _analyser.analyse("this.is.notavalidtoken!!")
    assert report.error is not None


def test_completely_invalid_string():
    report = _analyser.analyse("notaJWTatall")
    assert report.error is not None
