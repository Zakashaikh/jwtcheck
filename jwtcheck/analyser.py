"""
analyser.py — Decode and assess a JWT token without verifying its signature.

Stdlib only — uses utils.decode_jwt_parts() (base64 + json). No PyJWT
dependency, so the analyser works offline and on machines where PyJWT is not
installed. Intended for SOC / incident-response triage of captured tokens.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .rules import SEVERITY_ORDER
from .utils import decode_jwt_parts


def _max_severity(severities: List[str]) -> str:
    """Return the highest-ranked severity from a list; 'PASS' if empty."""
    return min(
        (s for s in severities if s in SEVERITY_ORDER),
        key=SEVERITY_ORDER.index,
        default="PASS",
    )


# ---------------------------------------------------------------------------
# Algorithm risk table
# ---------------------------------------------------------------------------

# Risk grading for the "alg" header.
#
# The HMAC family is graded uniformly. Recoverability of an HMAC key is a
# function of the *secret's entropy*, not of the digest length: RFC 8725 s2.2
# describes exactly this ("a weak symmetric key with insufficient entropy
# (such as a human-memorable password) ... vulnerable to offline brute-force"),
# and s3.5 makes it a MUST NOT. Grading HS256 above HS384/HS512 would imply an
# attack on SHA-256 that does not apply to SHA-512 at equal key entropy, which
# is not the case — and bruteforce.py attacks all three identically.
#
# On the asymmetric side: RFC 8725 s3.2 does NOT recommend RSASSA-PSS over
# RSASSA-PKCS1-v1_5 for signatures. Its PKCS#1 v1.5 warning concerns RSAES-
# PKCS1-v1_5 *encryption* (the Bleichenbacher target), which is a different
# primitive. PS is noted as preferable here on the strength of its security
# proof, but that is an engineering preference, not a specification
# requirement, and it is not given a different severity on that basis.
_HMAC_NOTE = (
    "Symmetric HMAC — security rests entirely on the entropy of the shared "
    "secret; offline brute-force is feasible against a weak one (RFC 8725 s2.2)."
)

ALGORITHM_RISK: Dict[str, tuple] = {
    "none":  ("CRITICAL", "Unsigned token — no signature at all."),

    "HS256": ("HIGH", _HMAC_NOTE),
    "HS384": ("HIGH", _HMAC_NOTE),
    "HS512": ("HIGH", _HMAC_NOTE),

    "RS256": ("LOW", "RSASSA-PKCS1-v1_5 — asymmetric, widely supported."),
    "RS384": ("LOW", "RSASSA-PKCS1-v1_5 — asymmetric, widely supported."),
    "RS512": ("LOW", "RSASSA-PKCS1-v1_5 — asymmetric, widely supported."),

    "ES256": ("LOW", "ECDSA — asymmetric; RFC 8725 s3.2 advises deterministic ECDSA (RFC 6979)."),
    "ES384": ("LOW", "ECDSA — asymmetric; RFC 8725 s3.2 advises deterministic ECDSA (RFC 6979)."),
    "ES512": ("LOW", "ECDSA — asymmetric; RFC 8725 s3.2 advises deterministic ECDSA (RFC 6979)."),

    "PS256": ("LOW", "RSASSA-PSS — asymmetric; preferable to PKCS#1 v1.5 on proof strength."),
    "PS384": ("LOW", "RSASSA-PSS — asymmetric; preferable to PKCS#1 v1.5 on proof strength."),
    "PS512": ("LOW", "RSASSA-PSS — asymmetric; preferable to PKCS#1 v1.5 on proof strength."),
}

# Case-insensitive index. The "alg" value is case-sensitive per RFC 7515, so a
# token presenting "None" or "NONE" is not a registered algorithm — but that is
# precisely the documented filter-bypass for the none-algorithm attack, and it
# must not be graded as merely unrecognised. Matching case-insensitively and
# flagging the mismatch separately is the behaviour the scanner already has
# (scanner.py lowercases before comparing), so this also removes a disagreement
# between the tool's two modes.
_ALG_INDEX: Dict[str, str] = {name.lower(): name for name in ALGORITHM_RISK}

# Algorithms whose secret can be brute-forced from a wordlist
_HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClaimFinding:
    """A single observation about a token claim."""
    claim: str
    severity: str
    message: str


@dataclass
class TokenReport:
    """Full assessment of a single JWT token."""
    raw_token: str
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    algorithm: Optional[str] = None
    alg_severity: Optional[str] = None
    alg_notes: Optional[str] = None
    claim_findings: List[ClaimFinding] = field(default_factory=list)
    header_findings: List[ClaimFinding] = field(default_factory=list)
    is_expired: bool = False
    seconds_until_expiry: Optional[int] = None
    brute_force_candidate: bool = False
    cracked_secret: Optional[str] = None
    error: Optional[str] = None

    def summary_severity(self) -> str:
        """
        Return the highest severity across the algorithm, claims, header
        injection vectors, and the brute-force outcome. A recovered secret is
        CRITICAL: the token can be forged outright.
        """
        severities: List[str] = []
        if self.alg_severity:
            severities.append(self.alg_severity)
        severities.extend(cf.severity for cf in self.claim_findings)
        severities.extend(hf.severity for hf in self.header_findings)
        if self.cracked_secret is not None:
            severities.append("CRITICAL")
        return _max_severity(severities)


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class Analyser:
    """Decodes and assesses JWT tokens without signature verification."""

    def analyse(self, token: str) -> TokenReport:
        """
        Perform a full assessment of a single JWT token.

        Args:
            token: A raw JWT string.

        Returns:
            A populated TokenReport. On a decode failure, report.error is set
            and the remaining fields are left at their defaults.
        """
        report = TokenReport(raw_token=token)

        # 1. Decode (stdlib only) — bail out cleanly on malformed input
        try:
            header, payload, _sig = decode_jwt_parts(token)
        except ValueError as exc:
            report.error = str(exc)
            return report

        report.header = header
        report.payload = payload

        # 2. Algorithm risk lookup (case-insensitive — see _ALG_INDEX)
        alg = header.get("alg")
        report.algorithm = alg

        if alg is None:
            # "alg" is REQUIRED by RFC 7515 s4.1.1. A token without one is
            # structurally invalid and cannot be verified as signed.
            report.alg_severity = "CRITICAL"
            report.alg_notes = (
                "No 'alg' header — REQUIRED by RFC 7515 s4.1.1. The token "
                "cannot be verified and must be rejected."
            )
        else:
            canonical = _ALG_INDEX.get(str(alg).lower())
            if canonical is None:
                report.alg_severity = "MEDIUM"
                report.alg_notes = f"Unrecognised algorithm '{alg}' — review manually."
            else:
                report.alg_severity, report.alg_notes = ALGORITHM_RISK[canonical]
                if alg != canonical:
                    # Registered names are case-sensitive, so a case variant is
                    # not a typo — it is the documented way of slipping a
                    # rejected algorithm past a case-sensitive allowlist.
                    report.alg_severity = "CRITICAL"
                    report.alg_notes = (
                        f"Algorithm '{alg}' differs in case from the registered "
                        f"name '{canonical}'. Registered 'alg' values are "
                        f"case-sensitive (RFC 7515), so this is characteristic of "
                        f"an attempt to bypass a case-sensitive allowlist. "
                        f"Underlying algorithm risk: {report.alg_notes}"
                    )

        # 3. Claim checks + header key-injection checks
        report.claim_findings = self._check_claims(payload)
        report.header_findings = self._check_header(header)

        # 4. Expiry computation
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            remaining = int(exp - time.time())
            report.seconds_until_expiry = remaining
            report.is_expired = remaining <= 0

        # 5. Brute-force candidacy (case-insensitive, for the same reason)
        report.brute_force_candidate = (
            _ALG_INDEX.get(str(alg).lower()) in _HMAC_ALGORITHMS
        )

        return report

    # ------------------------------------------------------------------
    # Claim assessment
    # ------------------------------------------------------------------

    def _check_claims(self, payload: Dict[str, Any]) -> List[ClaimFinding]:
        """Inspect standard claims and return a list of findings."""
        findings: List[ClaimFinding] = []
        now = time.time()

        exp = payload.get("exp")
        iat = payload.get("iat")

        # --- exp: presence and expiry ----------------------------------
        if exp is None:
            # HIGH, not CRITICAL: this must agree with R07, which grades the
            # same weakness HIGH in scan mode. Note also that RFC 7519 s4.1.4
            # makes "exp" OPTIONAL, so this is a policy judgement rather than a
            # specification violation.
            findings.append(ClaimFinding(
                "exp", "HIGH", "MISSING — token never expires."
            ))
        elif isinstance(exp, (int, float)):
            remaining = int(exp - now)
            if remaining <= 0:
                # An expired token is the expiry control working as intended.
                # It is worth surfacing during triage, but it is not itself a
                # weakness and should not inflate the token's overall severity.
                findings.append(ClaimFinding(
                    "exp", "LOW",
                    f"EXPIRED — token expired {abs(remaining)} seconds ago; "
                    f"a conformant verifier would reject it."
                ))

        # --- token lifetime (exp - iat > 24h) --------------------------
        if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
            lifetime = int(exp - iat)
            if lifetime > 86400:
                findings.append(ClaimFinding(
                    "exp", "HIGH",
                    f"Token lifetime is {lifetime} seconds (> 24 hours)."
                ))

        # --- iat: issued-at in the future suggests forgery -------------
        if isinstance(iat, (int, float)) and iat > now + 60:
            findings.append(ClaimFinding(
                "iat", "HIGH",
                "FUTURE IAT — token claims to be issued in the future."
            ))

        # --- aud -------------------------------------------------------
        if payload.get("aud") is None:
            findings.append(ClaimFinding(
                "aud", "MEDIUM",
                "MISSING — no audience restriction; token may be accepted by "
                "unintended services."
            ))

        # --- iss -------------------------------------------------------
        if payload.get("iss") is None:
            findings.append(ClaimFinding(
                "iss", "MEDIUM",
                "MISSING — no issuer; token origin cannot be verified."
            ))

        # --- nbf: not-before in the future -----------------------------
        nbf = payload.get("nbf")
        if isinstance(nbf, (int, float)) and nbf > now + 60:
            findings.append(ClaimFinding(
                "nbf", "MEDIUM",
                f"NOT YET VALID — token is not valid until {int(nbf)}."
            ))

        return findings

    # ------------------------------------------------------------------
    # Header key-injection assessment (jwk / jku / x5u / kid)
    # ------------------------------------------------------------------

    def _check_header(self, header: Dict[str, Any]) -> List[ClaimFinding]:
        """
        Inspect the JOSE header for key-injection attack vectors.

        These map directly to the PortSwigger JWT lab classes: an attacker who
        controls the header can point verification at a key they supply.
        """
        findings: List[ClaimFinding] = []

        # jwk — embedded public key in the header (CVE-class: self-signed token)
        if header.get("jwk") is not None:
            findings.append(ClaimFinding(
                "jwk", "HIGH",
                "Embedded JWK in header — token may be self-signed with an "
                "attacker-supplied key."
            ))

        # jku — URL the server fetches the verification key from (SSRF/injection)
        if header.get("jku") is not None:
            findings.append(ClaimFinding(
                "jku", "HIGH",
                f"jku header points to '{header.get('jku')}' — verification key "
                "is fetched from a URL; injection/SSRF risk."
            ))

        # x5u — X.509 certificate URL (same risk family as jku)
        if header.get("x5u") is not None:
            findings.append(ClaimFinding(
                "x5u", "HIGH",
                "x5u header references a remote certificate URL — injection/SSRF risk."
            ))

        # kid — key identifier; path traversal or SQLi if used to locate a key
        kid = header.get("kid")
        if isinstance(kid, str) and any(
            marker in kid for marker in ("../", "..\\", "/", "\\", "'", ";")
        ):
            findings.append(ClaimFinding(
                "kid", "HIGH",
                f"Suspicious kid value '{kid}' — possible path traversal or "
                "SQL injection in key lookup."
            ))

        return findings
