"""
bruteforce.py — HMAC secret recovery via wordlist.

Given a token signed with an HMAC algorithm (HS256/384/512), attempt to recover
the signing secret by testing each candidate in a wordlist. Used to demonstrate
the practical risk of weak symmetric secrets (R05, R06).

Note on the constant-time comparison
------------------------------------
Signature comparison uses ``hmac.compare_digest()`` rather than ``==``. It is
worth being accurate about why, because the obvious justification is wrong.

Constant-time comparison protects a *verifier*: there, the signature being
compared is a secret-dependent value an attacker may probe repeatedly, and a
short-circuiting ``==`` leaks how many leading bytes matched. None of that
applies here. In this code path JWTCheck is the attacking side — it already
holds the target signature in full and computes each candidate MAC locally, so
there is no remote observer and no secret to leak. Timing here is not a channel.

``compare_digest`` is kept for two lesser reasons: it keeps the comparison
consistent with how a correct verifier would perform it, so the module is not a
bad example to copy from; and the cost is irrelevant beside the HMAC
computation that precedes it. It is *not* a security property of this tool, and
earlier drafts of this project described it as one incorrectly.

Timeout handling is platform-aware: a ``signal.SIGALRM`` alarm is used on Unix,
falling back to a periodic wall-clock check on Windows (where SIGALRM is absent).
"""

import hashlib
import hmac
import json
import signal
import threading
import time
from typing import Callable, Optional

from .utils import base64url_decode


# Algorithm -> hash constructor
_HASH_FUNCS: dict = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


class _TimeoutReached(Exception):
    """Raised by the SIGALRM handler when the brute-force budget expires."""


def _raise_timeout(signum, frame):  # noqa: ANN001 - signal handler signature
    raise _TimeoutReached()


def crack(token: str, wordlist_path: str, timeout: int = 30) -> Optional[str]:
    """
    Attempt to recover the HMAC signing secret for a token from a wordlist.

    Args:
        token:         A raw JWT string signed with HS256/HS384/HS512.
        wordlist_path: Path to a newline-delimited candidate secret file.
        timeout:       Maximum seconds to spend before giving up.

    Returns:
        The cracked secret string on success, or None on timeout, exhaustion,
        or if the token does not use a supported HMAC algorithm.

    Raises:
        ValueError: If the token does not have exactly three parts.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid JWT structure: expected 3 parts, got {len(parts)}."
        )
    header_b64, payload_b64, signature_b64 = parts

    # Reconstruct the exact bytes that were signed.
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    # Decode the expected signature (re-add base64url padding via the helper).
    try:
        expected_sig = base64url_decode(signature_b64)
    except ValueError:
        return None

    # Determine the HMAC algorithm from the header.
    try:
        header = json.loads(base64url_decode(header_b64).decode("utf-8"))
    except ValueError:
        return None
    alg = header.get("alg")
    hash_fn: Optional[Callable] = _HASH_FUNCS.get(alg)
    if hash_fn is None:
        return None  # not an HMAC token — nothing to brute-force

    # Platform-aware timeout setup. SIGALRM only works in the main thread of
    # the main interpreter, so fall back to clock polling otherwise.
    use_sigalrm = (
        hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )
    previous_handler = None
    deadline = time.monotonic() + timeout

    if use_sigalrm:
        previous_handler = signal.signal(signal.SIGALRM, _raise_timeout)
        signal.alarm(timeout)

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for index, line in enumerate(fh):
                secret = line.rstrip("\n").rstrip("\r")
                if not secret:
                    continue

                # Windows fallback: no SIGALRM, so poll the clock periodically.
                if not use_sigalrm and index % 1000 == 0:
                    if time.monotonic() > deadline:
                        return None

                candidate_sig = hmac.new(
                    secret.encode("utf-8"), signing_input, hash_fn
                ).digest()

                # Constant-time comparison — never use ==.
                if hmac.compare_digest(candidate_sig, expected_sig):
                    return secret

    except _TimeoutReached:
        return None
    except OSError:
        return None
    finally:
        # Always cancel the alarm and restore the previous handler.
        if use_sigalrm:
            signal.alarm(0)
            if previous_handler is not None:
                signal.signal(signal.SIGALRM, previous_handler)

    return None
