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

ALGORITHM_RISK: Dict[str, tuple] = {
    "none":  ("CRITICAL", "Unsigned token — no signature at all."),

    "HS256": ("HIGH", "Symmetric HMAC-SHA256 — brute-forceable if the secret is weak."),
    "HS384": ("MEDIUM", "Symmetric HMAC — security depends entirely on secret strength."),
    "HS512": ("MEDIUM", "Symmetric HMAC — security depends entirely on secret strength."),

    "RS256": ("LOW", "RSA PKCS1v15 — asymmetric, widely supported."),
    "RS384": ("LOW", "RSA PKCS1v15 — asymmetric, widely supported."),
    "RS512": ("LOW", "RSA PKCS1v15 — asymmetric, widely supported."),

    "ES256": ("LOW", "ECDSA — asymmetric, strong choice."),
    "ES384": ("LOW", "ECDSA — asymmetric, strong choice."),
    "ES512": ("LOW", "ECDSA — asymmetric, strong choice."),

    "PS256": ("PASS", "RSA-PSS — recommended by RFC 8725."),
    "PS384": ("PASS", "RSA-PSS — recommended by RFC 8725."),
    "PS512": ("PASS", "RSA-PSS — recommended by RFC 8725."),
}

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

        # 2. Algorithm risk lookup
        alg = header.get("alg")
        report.algorithm = alg
        if alg in ALGORITHM_RISK:
            report.alg_severity, report.alg_notes = ALGORITHM_RISK[alg]
        else:
            report.alg_severity = "MEDIUM"
            report.alg_notes = f"Unrecognised algorithm '{alg}' — review manually."

        # 3. Claim checks + header key-injection checks
        report.claim_findings = self._check_claims(payload)
        report.header_findings = self._check_header(header)

        # 4. Expiry computation
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            remaining = int(exp - time.time())
            report.seconds_until_expiry = remaining
            report.is_expired = remaining <= 0

        # 5. Brute-force candidacy
        report.brute_force_candidate = alg in _HMAC_ALGORITHMS

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
            findings.append(ClaimFinding(
                "exp", "CRITICAL", "MISSING — token never expires."
            ))
        elif isinstance(exp, (int, float)):
            remaining = int(exp - now)
            if remaining <= 0:
                findings.append(ClaimFinding(
                    "exp", "HIGH",
                    f"EXPIRED — token expired {abs(remaining)} seconds ago."
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
