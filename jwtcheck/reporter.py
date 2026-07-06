"""
reporter.py — Output formatting for JWTCheck.

Scan mode  : render_text()  — coloured terminal report
             render_sarif() — valid SARIF 2.1.0 for GitHub Code Scanning
Analyse mode: render_token_report_text() — terminal token assessment
"""

import json
from typing import Dict, List

from .analyser import TokenReport
from .rules import all_rules
from .scanner import Finding
from .utils import severity_colour

# Severity ordering used for sorting summaries (highest first)
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]

# SARIF level mapping (per blueprint: CRITICAL->error, HIGH->warning, MEDIUM->note)
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "note",
    "INFO": "note",
}

_GREEN = "\033[92m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Scan mode — plain text
# ---------------------------------------------------------------------------

def render_text(findings: List[Finding], show_remediation: bool = True) -> str:
    """Render scan findings as a coloured terminal report."""
    if not findings:
        return f"{_GREEN}[✓] No JWT misuse patterns detected.{_RESET}"

    ordered = sorted(findings, key=lambda f: (f.filepath, f.line, f.col))
    lines: List[str] = []

    for f in ordered:
        location = f"{f.filepath}:{f.line}:{f.col}"
        lines.append(
            f"{severity_colour(f.severity)} {_BOLD}{f.rule_id}{_RESET} "
            f"{f.rule_name}"
        )
        lines.append(f"  {_DIM}{location}{_RESET}")
        if f.snippet:
            lines.append(f"    {f.snippet}")
        lines.append(f"  {f.description}")
        if f.cwe:
            lines.append(f"  {_DIM}Weakness: {f.cwe}{_RESET}")
        if show_remediation:
            lines.append(f"  {_BOLD}Fix:{_RESET} {f.remediation}")
        lines.append("")

    lines.append(_render_summary(findings))
    return "\n".join(lines)


def _render_summary(findings: List[Finding]) -> str:
    """Build a per-severity count summary line."""
    counts: Dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    parts = [
        f"{severity_colour(sev)}: {counts[sev]}"
        for sev in _SEVERITY_ORDER if counts[sev] > 0
    ]
    total = len(findings)
    return f"{_BOLD}Summary{_RESET} — {total} finding(s): " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Scan mode — SARIF 2.1.0
# ---------------------------------------------------------------------------

def render_sarif(findings: List[Finding], tool_version: str = "0.1.0") -> str:
    """Render scan findings as valid SARIF 2.1.0 JSON for GitHub Code Scanning."""
    # Each rule appears once in the driver's rules array.
    rule_index: Dict[str, int] = {}
    sarif_rules = []
    for rule in all_rules():
        rule_index[rule.id] = len(sarif_rules)
        sarif_rules.append({
            "id": rule.id,
            "name": rule.name.replace(" ", ""),
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "helpUri": (
                f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[1]}.html"
                if rule.cwe else "https://datatracker.ietf.org/doc/html/rfc8725"
            ),
            "help": {"text": rule.remediation},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(rule.severity, "warning")
            },
            "properties": {
                "security-severity": _security_severity(rule.severity),
                "tags": ["security", "jwt"],
                "cwe": rule.cwe,
            },
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.rule_name}: {f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.filepath.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, f.line),
                        "startColumn": max(1, f.col + 1),
                        "snippet": {"text": f.snippet},
                    },
                },
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "JWTCheck",
                    "version": tool_version,
                    "informationUri": "https://github.com/example/jwtcheck",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _security_severity(severity: str) -> str:
    """Map a severity label to a numeric GitHub security-severity score."""
    return {
        "CRITICAL": "9.5",
        "HIGH": "8.0",
        "MEDIUM": "5.5",
        "LOW": "3.0",
        "INFO": "1.0",
        "PASS": "0.0",
    }.get(severity, "5.5")


# ---------------------------------------------------------------------------
# Analyse mode — token report text
# ---------------------------------------------------------------------------

def render_token_report_text(report: TokenReport) -> str:
    """Render a TokenReport as a terminal assessment."""
    if report.error:
        return f"{severity_colour('HIGH')} Could not parse token: {report.error}"

    lines: List[str] = []

    # Algorithm
    lines.append(
        f"{_BOLD}Algorithm{_RESET}: {report.algorithm}  "
        f"[{severity_colour(report.alg_severity or 'INFO')}]"
    )
    if report.alg_notes:
        lines.append(f"  {report.alg_notes}")

    # Expiry status
    if report.seconds_until_expiry is None:
        lines.append(f"{_BOLD}Expiry{_RESET}: no exp claim present")
    elif report.is_expired:
        ago = abs(report.seconds_until_expiry)
        lines.append(f"{_BOLD}Expiry{_RESET}: {severity_colour('HIGH')} EXPIRED ({ago}s ago)")
    else:
        minutes = report.seconds_until_expiry // 60
        lines.append(
            f"{_BOLD}Expiry{_RESET}: valid, {report.seconds_until_expiry}s "
            f"(~{minutes} min) remaining"
        )

    # Brute-force status
    if report.cracked_secret is not None:
        lines.append(
            f"{_BOLD}Brute-force{_RESET}: {severity_colour('CRITICAL')} "
            f"SECRET CRACKED -> '{report.cracked_secret}'"
        )
    elif report.brute_force_candidate:
        lines.append(
            f"{_BOLD}Brute-force{_RESET}: HMAC token — candidate for wordlist "
            f"attack (supply --wordlist to attempt)"
        )

    # Header key-injection findings
    if report.header_findings:
        lines.append(f"{_BOLD}Header{_RESET}:")
        for hf in report.header_findings:
            lines.append(f"  [{severity_colour(hf.severity)}] {hf.claim}: {hf.message}")

    # Claim findings
    if report.claim_findings:
        lines.append(f"{_BOLD}Claims{_RESET}:")
        for cf in report.claim_findings:
            lines.append(f"  [{severity_colour(cf.severity)}] {cf.claim}: {cf.message}")

    # Decoded payload
    if report.payload:
        lines.append(f"{_BOLD}Decoded payload{_RESET}:")
        for k, v in report.payload.items():
            lines.append(f"  {k} = {v}")

    # Overall severity
    lines.append(
        f"{_BOLD}Overall severity{_RESET}: "
        f"{severity_colour(report.summary_severity())}"
    )

    return "\n".join(lines)
