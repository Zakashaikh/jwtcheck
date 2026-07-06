"""
test_reporter.py — output formatting tests (text + SARIF 2.1.0).
"""

import json

from jwtcheck.analyser import Analyser
from jwtcheck.reporter import (
    render_sarif,
    render_text,
    render_token_report_text,
)
from jwtcheck.rules import all_rules, get_rule
from jwtcheck.scanner import Finding


def _finding(rule_id: str, line: int = 1) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        description=rule.description,
        remediation=rule.remediation,
        filepath="example.py",
        line=line,
        col=0,
        snippet="jwt.decode(token, key)",
        cwe=rule.cwe,
    )


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def test_render_text_no_findings_is_green_ok():
    out = render_text([])
    assert "No JWT misuse patterns detected" in out


def test_render_text_includes_rule_and_summary():
    out = render_text([_finding("R01"), _finding("R07")])
    assert "R01" in out and "R07" in out
    assert "Summary" in out


def test_render_text_respects_no_remediation():
    out = render_text([_finding("R01")], show_remediation=False)
    assert "Fix:" not in out


def test_render_text_sorted_by_location():
    out = render_text([_finding("R01", line=50), _finding("R07", line=2)])
    # The line=2 finding must appear before the line=50 finding.
    assert out.index(":2:") < out.index(":50:")


# ---------------------------------------------------------------------------
# SARIF rendering
# ---------------------------------------------------------------------------

def test_sarif_is_valid_json_with_correct_schema():
    doc = json.loads(render_sarif([_finding("R01")]))
    assert doc["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
        "Schemata/sarif-schema-2.1.0.json"
    )
    assert doc["version"] == "2.1.0"


def test_sarif_contains_all_rules_once():
    doc = json.loads(render_sarif([]))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(all_rules())
    assert len(ids) == len(set(ids))  # no duplicates


def test_sarif_result_has_physical_location():
    doc = json.loads(render_sarif([_finding("R01", line=7)]))
    result = doc["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert loc["region"]["startLine"] == 7
    assert result["level"] == "error"   # CRITICAL -> error


def test_sarif_level_mapping():
    doc = json.loads(render_sarif([_finding("R07"), _finding("R08")]))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["R07"] == "warning"   # HIGH -> warning
    assert levels["R08"] == "note"      # MEDIUM -> note


# ---------------------------------------------------------------------------
# Token report rendering
# ---------------------------------------------------------------------------

def test_render_token_report_error_path():
    report = Analyser().analyse("notavalidtoken")
    out = render_token_report_text(report)
    assert "Could not parse token" in out


def test_render_token_report_shows_algorithm_and_payload():
    import base64
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = b64({"alg": "HS256"}) + "." + b64({"sub": "alice"}) + ".sig"
    report = Analyser().analyse(token)
    out = render_token_report_text(report)
    assert "HS256" in out
    assert "alice" in out
    assert "Overall severity" in out
