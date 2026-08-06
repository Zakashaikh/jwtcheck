"""
utils.py — Shared helper functions for JWTCheck.

All JWT decoding here uses stdlib only (base64, json) — no PyJWT dependency.
This ensures the token analyser works fully offline.
"""

import base64
import json
import re
from typing import Tuple, List


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

# The base64url alphabet of RFC 4648 s5: A-Z a-z 0-9 '-' '_'. Deliberately
# excludes '+' and '/', which are base64 but not base64url. An empty segment
# is permitted, since a JWS with an empty signature (alg=none) is well-formed.
_B64URL_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


def base64url_decode(segment: str) -> bytes:
    """
    Decode a base64url-encoded segment (as used in JWT parts).

    Adds the required padding before decoding, as JWT segments omit
    trailing '=' characters per RFC 7515 §2.

    Args:
        segment: A base64url-encoded string (no padding).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the segment is not valid base64url.
    """
    # Reject anything outside the base64url alphabet BEFORE normalising.
    #
    # base64.b64decode() without validate=True silently discards characters
    # outside the alphabet, so a segment containing '*' or '#' would decode
    # happily and the tool would report on a token no conformant verifier
    # would accept. Checking first, and checking against the base64URL
    # alphabet specifically, also rejects literal '+' and '/' — which are
    # valid base64 but NOT valid base64url (RFC 7515 s2, RFC 4648 s5).
    if not _B64URL_ALPHABET.fullmatch(segment):
        raise ValueError(
            "Segment contains characters outside the base64url alphabet"
        )

    # Normalise: replace URL-safe chars with standard base64 chars
    segment = segment.replace("-", "+").replace("_", "/")

    # Re-add padding — base64 requires length divisible by 4
    padding_needed = len(segment) % 4
    if padding_needed == 2:
        segment += "=="
    elif padding_needed == 3:
        segment += "="
    elif padding_needed == 1:
        # A remainder of 1 is never valid in base64
        raise ValueError(f"Invalid base64url segment length: {len(segment)}")

    try:
        return base64.b64decode(segment, validate=True)
    except Exception as exc:
        raise ValueError(f"Malformed base64url segment: {exc}") from exc


# ---------------------------------------------------------------------------
# JWT structure decoder (stdlib only — no PyJWT)
# ---------------------------------------------------------------------------

def decode_jwt_parts(token: str) -> Tuple[dict, dict, str]:
    """
    Split and decode a JWT token into its three parts using stdlib only.

    Does NOT verify the signature — intended for inspection and analysis.

    Args:
        token: A raw JWT string (three base64url segments separated by '.').

    Returns:
        Tuple of (header_dict, payload_dict, raw_signature_segment).

    Raises:
        ValueError: If the token does not have exactly three parts, or if
                    the header/payload segments are not valid JSON.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid JWT structure: expected 3 parts, got {len(parts)}."
        )

    header_seg, payload_seg, sig_seg = parts

    try:
        header_bytes = base64url_decode(header_seg)
    except ValueError as exc:
        raise ValueError(f"Cannot decode JWT header: {exc}") from exc

    try:
        payload_bytes = base64url_decode(payload_seg)
    except ValueError as exc:
        raise ValueError(f"Cannot decode JWT payload: {exc}") from exc

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"JWT header is not valid JSON: {exc}") from exc

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"JWT payload is not valid JSON: {exc}") from exc

    return header, payload, sig_seg


# ---------------------------------------------------------------------------
# Token extraction from arbitrary text (log files, etc.)
# ---------------------------------------------------------------------------

# Pattern: three base64url segments separated by dots.
# The header segment must be ≥ 16 chars (a JWT header is always at least this
# long once base64url-encoded), the payload ≥ 10, and the signature may be
# EMPTY — an `alg:none` token is `header.payload.` with no signature, and that
# is precisely the forgery the tool exists to detect, so it must not be excluded.
_JWT_PATTERN = re.compile(
    r"(?<![.\w])"            # not preceded by dot or word char
    r"([A-Za-z0-9\-_]{16,}"  # header segment (≥ 16 chars)
    r"\.[A-Za-z0-9\-_]{10,}" # payload segment (≥ 10 chars)
    r"\.[A-Za-z0-9\-_]*)"    # signature segment (≥ 0 chars — empty for alg:none)
    r"(?![\w])"              # not followed by a word char (a trailing dot is allowed)
)


def extract_tokens_from_text(text: str) -> List[str]:
    """
    Find JWT-like strings in arbitrary text (log files, HTTP responses, etc.).

    Uses a regex that matches three base64url segments separated by dots,
    with minimum per-segment lengths to reduce false positives.

    Args:
        text: Any string that may contain embedded JWT tokens.

    Returns:
        List of candidate JWT strings (may include false positives).
    """
    return _JWT_PATTERN.findall(text)


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"

_SEVERITY_COLOURS = {
    "CRITICAL": "\033[1;91m",   # bright red + bold
    "HIGH":     "\033[91m",     # red
    "MEDIUM":   "\033[93m",     # yellow
    "LOW":      "\033[96m",     # cyan
    "INFO":     "\033[94m",     # blue
    "PASS":     "\033[92m",     # green
}


def severity_colour(severity: str) -> str:
    """
    Return the severity label wrapped in ANSI colour codes.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO.

    Returns:
        Coloured string suitable for terminal output.
    """
    colour = _SEVERITY_COLOURS.get(severity.upper(), "")
    return f"{colour}{severity.upper()}{_RESET}"


# Regex to strip all ANSI escape sequences
_ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """
    Remove ANSI escape codes from a string.

    Used when writing terminal output to a plain-text file so that
    escape sequences do not appear as literal characters.

    Args:
        text: String potentially containing ANSI escape codes.

    Returns:
        Clean string with all ANSI codes removed.
    """
    return _ANSI_ESCAPE.sub("", text)
