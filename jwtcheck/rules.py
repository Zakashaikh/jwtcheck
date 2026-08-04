"""
rules.py — Detection rule registry for JWTCheck.

The 15 rules are adapted from the JWTKey framework (Xu et al., JWTKey,
ESORICS 2023) — originally Java-only — to the Python/PyJWT ecosystem, organised
by the five attack classes documented in the dissertation (Table 2.1).

Note on attack classes: these describe the *weakness* each rule detects in
source code. JWK/jku header injection is deliberately absent here — it is not
statically detectable from a call site, and is assessed by the token analyser
against a decoded header instead (see analyser.py, header key-injection
assessment).

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
                           # missing_claims | verification_disabled
    cwe: Optional[str] = None
    cve_example: Optional[str] = None


# Canonical severity ordering (worst first). Single source of truth — the
# analyser, reporter, and CLI all rank findings against this list.
SEVERITY_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]


RULES: Dict[str, Rule] = {

    # ===================================================================
    # Attack Class 1 — None-algorithm acceptance (PyJWT < 2.0)
    #
    # No CVE is assigned to PyJWT for this class. Before 2.0 the algorithms
    # parameter was optional, so the weakness was an insecure API default
    # rather than a library defect; PyJWT 2.0 made the parameter mandatory.
    # CVE-2015-9235 is sometimes cited here but was assigned to
    # node-jsonwebtoken, not PyJWT — see NVD. The absence of a CVE is itself
    # evidence for the dissertation's argument (Section 2.6.2) that
    # application-level misuse goes unrecorded in the CVE system.
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
    ),

    # ===================================================================
    # R03 — Attack Class 5 (verification explicitly disabled). Grouped with
    # R11 and R13; all three are options={'verify_*': False} overrides.
    # ===================================================================

    "R03": Rule(
        id="R03",
        name="SignatureVerificationDisabled",
        description="options={'verify_signature': False} is passed to jwt.decode(), disabling all signature verification.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_signature override so PyJWT verifies the signature.",
        attack_class="verification_disabled",
        cwe="CWE-347",
    ),

    # ===================================================================
    # Attack Class 2 — Algorithm confusion (R04, R15)
    # CVE-2017-11424 (PyJWT <= 1.5.0) and CVE-2022-29217 (1.5.0-2.3.0,
    # fixed in 2.4.0): a PEM-encoded RSA public key is accepted as an HMAC
    # secret, letting an attacker forge tokens using the issuer's own
    # public key. NOT CVE-2022-21449, which is an Oracle Java SE ECDSA
    # signature-verification bypass and does not affect PyJWT.
    # ===================================================================

    "R04": Rule(
        id="R04",
        name="AlgorithmConfusionHsRs",
        description="The algorithms list contains both an HMAC variant and an RSA/ECDSA variant, enabling key-confusion attacks.",
        severity="CRITICAL",
        category="ALGORITHM",
        remediation="Pin a single algorithm family; never allow HMAC and asymmetric algorithms together.",
        attack_class="alg_confusion",
        cwe="CWE-327",
        cve_example="CVE-2022-29217",
    ),

    # ===================================================================
    # Attack Class 3 — Weak or exposed key material (R05, R06, R14)
    # No PyJWT CVE: recovering a key from source is application-level
    # misuse, not a library defect.
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
    # Attack Class 4 — Missing or misconfigured claims (R07-R10, R12)
    # CVE-2024-53861 (PyJWT 2.10.0, fixed 2.10.1): the iss claim was
    # compared by substring containment, so a wrong issuer could match.
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
        cve_example="CVE-2024-53861",
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
    # Attack Class 5 — Verification explicitly disabled (R03, R11, R13)
    # All three are options={'verify_*': False} overrides: the developer
    # switches off a check PyJWT performs by default. No PyJWT CVE, since
    # the library behaves as documented; the weakness is the override.
    # ===================================================================

    "R11": Rule(
        id="R11",
        name="IssuerVerificationDisabled",
        description="options={'verify_iss': False} is passed to jwt.decode(), disabling issuer verification.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_iss override so PyJWT validates the issuer.",
        attack_class="verification_disabled",
        cwe="CWE-347",
    ),

    # --- R12 belongs to Attack Class 4 (misconfigured claims) -----------

    "R12": Rule(
        id="R12",
        name="ExcessiveLeeway",
        description="The leeway argument to jwt.decode() exceeds 300 seconds, widening the window for expired tokens.",
        severity="MEDIUM",
        category="CONFIGURATION",
        remediation="Keep leeway at or below 60 seconds; rely on NTP for clock synchronisation.",
        attack_class="missing_claims",
        cwe="CWE-613",
    ),

    "R13": Rule(
        id="R13",
        name="ExpiryVerificationDisabled",
        description="options={'verify_exp': False} is passed to jwt.decode(), disabling expiry checking.",
        severity="CRITICAL",
        category="VERIFICATION",
        remediation="Remove the verify_exp override so PyJWT enforces token expiry.",
        attack_class="verification_disabled",
        cwe="CWE-347",
    ),

    # --- R14 belongs to Attack Class 3 (exposed key material) ----------

    "R14": Rule(
        id="R14",
        name="RsaKeyAsStringLiteral",
        description="An RSA/PEM key is passed to jwt.decode() as a plain string literal rather than bytes loaded from a file.",
        severity="HIGH",
        category="SECRET",
        remediation="Load PEM key material as bytes from a file or secrets store, not a source-code string literal.",
        attack_class="weak_secret",
        cwe="CWE-798",
    ),

    # --- R15 belongs to Attack Class 2 (algorithm confusion) -----------

    "R15": Rule(
        id="R15",
        name="AlgorithmNotPinnedEnvSecret",
        description="The verification key comes from os.environ but the algorithms list is not pinned to a single algorithm.",
        severity="MEDIUM",
        category="ALGORITHM",
        remediation="Pin algorithms to a single expected algorithm even when the key is loaded from the environment.",
        attack_class="alg_confusion",
        cwe="CWE-757",
        cve_example="CVE-2022-29217",
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
