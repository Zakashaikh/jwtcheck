"""
rules.py — Detection rule registry for JWTCheck.

The 15 rules are adapted from the JWTKey framework (Xu et al., JWTKey,
ESORICS 2023) — originally Java-only — to the Python/PyJWT ecosystem, organised
by the five attack classes documented in the dissertation (Table 2.1).

This module is the single source of truth: the scanner, reporter, and SARIF
output all read rule metadata from here. Pure data — no logic.
"""

from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass(frozen=True)
class Rule:
    """Immutable descriptor for a single detection rule."""
    id: str                # "R01" .. "R15"
    name: str              # short PascalCase/snake_case identifier
    description: str       # one sentence: what is wrong
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM"
    category: str          # ALGORITHM | VERIFICATION | SECRET | CLAIMS | CONFIGURATION
    remediation: str       # one sentence: how to fix it
    attack_class: str      # none_algorithm | alg_confusion | weak_secret |
                           # missing_claims | jwk_injection
    cwe: Optional[str] = None
    cve_example: Optional[str] = None


RULES: Dict[str, Rule] = {

    # ===================================================================
    # Attack Class 1 — None algorithm (CVE-2015-9235, PyJWT < 2.0)
    # ===================================================================

    "R01": Rule(
        id="R01",
        name="MissingAlgorithmsParameter",
        description="jwt.decode() is called with no algorithms parameter, allowing the token header to select the verification algorithm.",
        severity="CRITICAL",
        category="ALGORITHM",
        remediation="Always pass algorithms= explicitly, e.g. jwt.decode(token, key, algorithms=['HS256']).",
        attack_class="none_algorithm",
        cwe="CWE-757",
        cve_example="CVE-2015-9235",
    ),

    "R02": Rule(
        id="R02",
        name="NoneAlgorithmAccepted",
        description="The 'none' algorithm is present in the algorithms list, so an unsigned token would be accepted.",
        severity="CRITICAL",
        category="ALGORITHM",
        remediation="Remove 'none' from the algorithms list and pin a concrete algorithm such as HS256 or RS256.",
        attack_class="none_algorithm",
        cwe="CWE-347",
        cve_example="CVE-2015-9235",
    ),

    # ===================================================================
    # Attack Class 2 — Algorithm confusion (CVE-2022-21449, PyJWT < 2.4)
    # ===================================================================

    "R03": Rule(
        id="R03",
        name="SignatureVerificationDisabled",
        description="options={'verify_signature': False} is passed to jwt.decode(), disabling all signature verification.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_signature override so PyJWT verifies the signature.",
        attack_class="alg_confusion",
        cwe="CWE-347",
    ),

    "R04": Rule(
        id="R04",
        name="AlgorithmConfusionHsRs",
        description="The algorithms list contains both an HMAC variant and an RSA/ECDSA variant, enabling key-confusion attacks.",
        severity="CRITICAL",
        category="ALGORITHM",
        remediation="Pin a single algorithm family; never allow HMAC and asymmetric algorithms together.",
        attack_class="alg_confusion",
        cwe="CWE-327",
        cve_example="CVE-2022-21449",
    ),

    # ===================================================================
    # Attack Class 3 — Weak HMAC secret
    # ===================================================================

    "R05": Rule(
        id="R05",
        name="HardcodedSecretEncode",
        description="A hardcoded string literal is used as the signing key in jwt.encode().",
        severity="HIGH",
        category="SECRET",
        remediation="Load the secret from an environment variable or secrets manager, never a source-code literal.",
        attack_class="weak_secret",
        cwe="CWE-798",
    ),

    "R06": Rule(
        id="R06",
        name="HardcodedSecretDecode",
        description="A hardcoded string literal is used as the verification key in jwt.decode().",
        severity="HIGH",
        category="SECRET",
        remediation="Load the verification key from an environment variable or secrets manager, never a source-code literal.",
        attack_class="weak_secret",
        cwe="CWE-798",
    ),

    # ===================================================================
    # Attack Class 4 — Missing and misconfigured claims
    # ===================================================================

    "R07": Rule(
        id="R07",
        name="MissingExpClaim",
        description="jwt.encode() is called with a payload dict that has no 'exp' key, producing a token that never expires.",
        severity="HIGH",
        category="CLAIMS",
        remediation="Add an 'exp' claim to the payload so tokens expire.",
        attack_class="missing_claims",
        cwe="CWE-613",
    ),

    "R08": Rule(
        id="R08",
        name="MissingAudienceValidation",
        description="jwt.decode() is called with no audience parameter, so tokens are not bound to this service.",
        severity="MEDIUM",
        category="CLAIMS",
        remediation="Pass audience= to jwt.decode() to bind tokens to the intended service.",
        attack_class="missing_claims",
        cwe="CWE-346",
    ),

    "R09": Rule(
        id="R09",
        name="MissingIssuerValidation",
        description="jwt.decode() is called with no issuer parameter, so the token's origin is not verified.",
        severity="MEDIUM",
        category="CLAIMS",
        remediation="Pass issuer= to jwt.decode() to verify the token's origin.",
        attack_class="missing_claims",
        cwe="CWE-346",
    ),

    "R10": Rule(
        id="R10",
        name="ExcessiveTokenLifetime",
        description="A payload sets exp and iat as integer literals whose difference exceeds 86400 seconds (24 hours).",
        severity="HIGH",
        category="CLAIMS",
        remediation="Reduce the token lifetime; prefer short-lived access tokens with refresh tokens.",
        attack_class="missing_claims",
        cwe="CWE-613",
    ),

    # ===================================================================
    # Attack Class 5 — JWK/jku injection (PyJWT < 2.0)
    # ===================================================================

    "R11": Rule(
        id="R11",
        name="IssuerVerificationDisabled",
        description="options={'verify_iss': False} is passed to jwt.decode(), disabling issuer verification.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_iss override so PyJWT validates the issuer.",
        attack_class="jwk_injection",
        cwe="CWE-347",
    ),

    "R12": Rule(
        id="R12",
        name="ExcessiveLeeway",
        description="The leeway argument to jwt.decode() exceeds 300 seconds, widening the window for expired tokens.",
        severity="MEDIUM",
        category="CONFIGURATION",
        remediation="Keep leeway at or below 60 seconds; rely on NTP for clock synchronisation.",
        attack_class="jwk_injection",
        cwe="CWE-613",
    ),

    "R13": Rule(
        id="R13",
        name="ExpiryVerificationDisabled",
        description="options={'verify_exp': False} is passed to jwt.decode(), disabling expiry checking.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_exp override so PyJWT enforces token expiry.",
        attack_class="jwk_injection",
        cwe="CWE-347",
    ),

    "R14": Rule(
        id="R14",
        name="RsaKeyAsStringLiteral",
        description="An RSA/PEM key is passed to jwt.decode() as a plain string literal rather than bytes loaded from a file.",
        severity="HIGH",
        category="SECRET",
        remediation="Load PEM key material as bytes from a file or secrets store, not a source-code string literal.",
        attack_class="jwk_injection",
        cwe="CWE-798",
    ),

    "R15": Rule(
        id="R15",
        name="AlgorithmNotPinnedEnvSecret",
        description="The verification key comes from os.environ but the algorithms list is not pinned to a single algorithm.",
        severity="MEDIUM",
        category="ALGORITHM",
        remediation="Pin algorithms to a single expected algorithm even when the key is loaded from the environment.",
        attack_class="jwk_injection",
        cwe="CWE-757",
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_rule(rule_id: str) -> Optional[Rule]:
    """Return the Rule for the given ID, or None if not found."""
    return RULES.get(rule_id)


def all_rules() -> List[Rule]:
    """Return all 15 rules ordered by rule ID."""
    return [RULES[k] for k in sorted(RULES)]
