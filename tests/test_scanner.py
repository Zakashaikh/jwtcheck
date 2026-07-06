"""
test_scanner.py — one test per rule (R01–R15) plus safe-code negatives.

Each vulnerable fixture under tests/fixtures/vulnerable/ is named rNN_*.py and
must cause rule RNN to fire. Safe fixtures must yield zero findings.
"""

import os
import textwrap
import tempfile

import pytest

from jwtcheck.scanner import Scanner
from jwtcheck.rules import RULES

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
VULN = os.path.join(FIX, "vulnerable")
SAFE = os.path.join(FIX, "safe")

scanner = Scanner()


def _scan_snippet(code: str):
    """Write a snippet to a temp .py file, scan it, return the findings list."""
    code = textwrap.dedent(code)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(code)
        path = fh.name
    try:
        return scanner.scan_file(path)
    finally:
        os.unlink(path)


def _ids(findings):
    return {f.rule_id for f in findings}


def _fixture_for(rule_id):
    matches = [f for f in os.listdir(VULN) if f.lower().startswith(rule_id.lower())]
    assert matches, f"no fixture file for {rule_id}"
    return os.path.join(VULN, matches[0])


# ---------------------------------------------------------------------------
# One test per rule, driven by the on-disk fixtures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", [f"R{n:02d}" for n in range(1, 16)])
def test_rule_fires_on_its_fixture(rule_id):
    findings = scanner.scan_file(_fixture_for(rule_id))
    assert rule_id in _ids(findings), f"{rule_id} did not fire"


@pytest.mark.parametrize("rule_id", [f"R{n:02d}" for n in range(1, 16)])
def test_fixture_finding_has_correct_severity(rule_id):
    findings = scanner.scan_file(_fixture_for(rule_id))
    finding = next(f for f in findings if f.rule_id == rule_id)
    assert finding.severity == RULES[rule_id].severity


# ---------------------------------------------------------------------------
# Safe fixtures — zero findings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname", sorted(os.listdir(SAFE)))
def test_safe_fixture_has_no_findings(fname):
    findings = scanner.scan_file(os.path.join(SAFE, fname))
    assert findings == [], f"{fname} produced {_ids(findings)}"


def test_correct_usage_has_no_critical():
    findings = scanner.scan_file(os.path.join(SAFE, "correct_usage.py"))
    assert not any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# Targeted behavioural checks (inline snippets)
# ---------------------------------------------------------------------------

def test_r02_none_case_insensitive():
    findings = _scan_snippet('import jwt\njwt.decode(t, k, algorithms=["NONE"])')
    assert "R02" in _ids(findings)


def test_r07_resolves_variable_payload():
    findings = _scan_snippet(
        'import jwt\n'
        'payload = {"sub": "u"}\n'
        'jwt.encode(payload, key, algorithm="HS256")\n'
    )
    assert "R07" in _ids(findings)


def test_r05_not_triggered_by_env_secret():
    findings = _scan_snippet(
        'import jwt, os\n'
        'jwt.encode({"exp": 1}, os.environ["S"], algorithm="HS256")\n'
    )
    assert "R05" not in _ids(findings)


def test_aliased_import_detected():
    findings = _scan_snippet('import jwt as j\nj.decode(t, k)')
    assert "R01" in _ids(findings)


def test_bytes_decode_not_flagged():
    findings = _scan_snippet('data = b"x"\nresult = data.decode("utf-8")')
    assert findings == []


# ---------------------------------------------------------------------------
# Positional-argument handling (PyJWT accepts algorithms/options positionally).
# Regression guard for the false positive found during the real-world study.
# ---------------------------------------------------------------------------

def test_positional_algorithms_not_flagged_r01():
    # jwt.decode(token, key, "HS256") pins the algorithm positionally -> no R01.
    findings = _scan_snippet(
        'import jwt\n'
        'jwt.decode(t, k, "HS256", audience="a", issuer="i")\n'
    )
    assert "R01" not in _ids(findings)


def test_singular_algorithm_keyword_still_flagged_r01():
    # algorithm= (singular) is NOT a valid PyJWT decode parameter -> R01 stands.
    findings = _scan_snippet('import jwt\njwt.decode(t, k, algorithm="HS256")')
    assert "R01" in _ids(findings)


def test_positional_none_algorithm_flagged_r02():
    findings = _scan_snippet(
        'import jwt\njwt.decode(t, k, ["none"], audience="a", issuer="i")'
    )
    assert "R02" in _ids(findings)


def test_positional_options_verify_signature_flagged_r03():
    findings = _scan_snippet(
        'import jwt\n'
        'jwt.decode(t, k, ["HS256"], {"verify_signature": False}, '
        'audience="a", issuer="i")\n'
    )
    assert "R03" in _ids(findings)


# ---------------------------------------------------------------------------
# Verification-disabled suppression: when verify_signature is False the token
# is not trusted, so R01/R08/R09 are moot and only R03 should be raised.
# Informed by the real-world study (all false positives were intentional
# unverified decoding).
# ---------------------------------------------------------------------------

def test_verify_signature_false_raises_only_r03():
    findings = _scan_snippet(
        'import jwt\n'
        'jwt.decode(token, options={"verify_signature": False})\n'
    )
    ids = _ids(findings)
    assert "R03" in ids
    assert "R01" not in ids  # no algorithms is moot when nothing is verified
    assert "R08" not in ids
    assert "R09" not in ids


def test_deprecated_verify_false_raises_r03_not_r01():
    findings = _scan_snippet('import jwt\njwt.decode(idtoken, verify=False)')
    ids = _ids(findings)
    assert "R03" in ids
    assert "R01" not in ids


def test_verified_decode_still_flags_r08_r09():
    # Regression guard: normal (verified) decode must still raise R08/R09.
    findings = _scan_snippet(
        'import jwt\njwt.decode(token, key, algorithms=["HS256"])'
    )
    ids = _ids(findings)
    assert "R08" in ids
    assert "R09" in ids
