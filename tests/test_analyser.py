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


# ---------------------------------------------------------------------------
# Algorithm header handling — regression tests
#
# A case-variant "alg" is the documented way of slipping a rejected algorithm
# past a case-sensitive allowlist, so it must not be graded as merely
# unrecognised. The scanner already lowercases before comparing; these tests
# pin the analyser to the same behaviour so the two modes cannot drift apart.
# ---------------------------------------------------------------------------

def _token_with_alg(alg) -> str:
    """Hand-build a token so an arbitrary (or absent) alg can be set."""
    import base64
    import json

    def seg(obj) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = {"typ": "JWT"} if alg is None else {"alg": alg, "typ": "JWT"}
    return f"{seg(header)}.{seg({'sub': '1'})}.sig"


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE"])
def test_none_algorithm_detected_in_any_case(alg):
    report = _analyser.analyse(_token_with_alg(alg))
    assert report.alg_severity == "CRITICAL", (
        f"alg={alg!r} must be CRITICAL, not treated as unrecognised"
    )


def test_missing_alg_header_is_critical():
    # "alg" is REQUIRED by RFC 7515 s4.1.1.
    report = _analyser.analyse(_token_with_alg(None))
    assert report.alg_severity == "CRITICAL"
    assert "RFC 7515" in (report.alg_notes or "")


def test_case_variant_is_flagged_as_bypass_attempt():
    report = _analyser.analyse(_token_with_alg("hs256"))
    assert report.alg_severity == "CRITICAL"
    assert "differs in case" in (report.alg_notes or "")
    # still recognised as HMAC, so still worth brute-forcing
    assert report.brute_force_candidate is True


def test_hmac_family_graded_uniformly():
    # Recoverability depends on secret entropy, not digest length.
    sevs = {
        _analyser.analyse(_token_with_alg(a)).alg_severity
        for a in ("HS256", "HS384", "HS512")
    }
    assert len(sevs) == 1, f"HMAC variants graded inconsistently: {sevs}"


def test_unrecognised_algorithm_still_surfaces():
    report = _analyser.analyse(_token_with_alg("FOO123"))
    assert report.alg_severity == "MEDIUM"
