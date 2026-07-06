"""
corpus_spec.py — labelled evaluation benchmark for the JWTCheck scanner.

Each Sample pairs a Python snippet with the set of rule IDs that SHOULD be
reported for it (ground truth), reasoned independently from the rule
definitions in jwtcheck/rules.py (NOT from the tool's output).

Ground-truth labelling note
---------------------------
Three decode rules fire on any jwt.decode() that omits the relevant argument:
R01 (no algorithms), R08 (no audience), R09 (no issuer). Samples that target a
different rule therefore include algorithms=, audience= and issuer= so the
target rule is isolated; where those arguments are genuinely absent, R01/R08/R09
are part of the ground truth because the code genuinely exhibits them.

Severities/IDs follow the dissertation blueprint (Table 2.1).
"""

from dataclasses import dataclass
from typing import List, Set

# Decode arguments that mitigate the always-on decode rules, used to isolate
# a single target rule in a sample.
_PIN = 'algorithms=["HS256"], audience="a", issuer="i"'


@dataclass
class Sample:
    name: str
    code: str
    expected: Set[str]
    category: str          # "vulnerable" | "safe"
    note: str = ""


def _s(name, code, expected, category="vulnerable", note=""):
    return Sample(name, code, set(expected), category, note)


SAMPLES: List[Sample] = [

    # ----- R01: no algorithms parameter ----------------------------------
    _s("r01_no_algorithms",
       'import jwt\njwt.decode(token, key)\n',
       {"R01", "R08", "R09"},
       note="no algorithms, audience or issuer"),

    _s("r01_aliased_import",
       'import jwt as j\nj.decode(token, key)\n',
       {"R01", "R08", "R09"},
       note="aliased import, no algorithms"),

    # ----- R02: none algorithm -------------------------------------------
    _s("r02_none_isolated",
       f'import jwt\njwt.decode(token, key, {_PIN.replace("HS256", "none")})\n',
       {"R02"},
       note="algorithms=['none'] isolated"),

    _s("r02_none_mixed",
       'import jwt\njwt.decode(token, key, algorithms=["HS256", "none"], '
       'audience="a", issuer="i")\n',
       {"R02"},
       note="none mixed with a real algorithm"),

    # ----- R03: verify_signature False -----------------------------------
    _s("r03_verify_signature_false",
       f'import jwt\njwt.decode(token, key, {_PIN}, '
       'options={"verify_signature": False})\n',
       {"R03"}),

    # ----- R04: algorithm confusion (HS + RS) ----------------------------
    _s("r04_hs_rs",
       'import jwt\njwt.decode(token, key, algorithms=["HS256", "RS256"], '
       'audience="a", issuer="i")\n',
       {"R04"}),

    _s("r04_hs_es",
       'import jwt\njwt.decode(token, key, algorithms=["HS384", "ES256"], '
       'audience="a", issuer="i")\n',
       {"R04"}),

    # ----- R05: hardcoded secret in encode -------------------------------
    _s("r05_hardcoded_encode",
       'import jwt\njwt.encode({"exp": 1700000000}, "mysecret", algorithm="HS256")\n',
       {"R05"}),

    # ----- R06: hardcoded secret in decode -------------------------------
    _s("r06_hardcoded_decode",
       f'import jwt\njwt.decode(token, "mysecret", {_PIN})\n',
       {"R06"}),

    # ----- R07: missing exp in encode ------------------------------------
    _s("r07_no_exp_inline",
       'import jwt\njwt.encode({"sub": "u"}, key, algorithm="HS256")\n',
       {"R07"}),

    _s("r07_no_exp_variable",
       'import jwt\npayload = {"sub": "u"}\n'
       'jwt.encode(payload, key, algorithm="HS256")\n',
       {"R07"},
       note="variable-resolved payload (hard case)"),

    # ----- R08 / R09: missing aud / iss ----------------------------------
    _s("r08_no_audience",
       'import jwt\njwt.decode(token, key, algorithms=["HS256"], issuer="i")\n',
       {"R08"}),

    _s("r09_no_issuer",
       'import jwt\njwt.decode(token, key, algorithms=["HS256"], audience="a")\n',
       {"R09"}),

    _s("r08_r09_both",
       'import jwt\njwt.decode(token, key, algorithms=["HS256"])\n',
       {"R08", "R09"}),

    # ----- R10: excessive lifetime (exp - iat > 86400) -------------------
    _s("r10_excessive_lifetime",
       'import jwt\npayload = {"iat": 1700000000, "exp": 1700200000}\n'
       'jwt.encode(payload, key, algorithm="HS256")\n',
       {"R10"},
       note="exp - iat = 200000s > 86400"),

    _s("r10_inline_lifetime",
       'import jwt\njwt.encode({"iat": 1700000000, "exp": 1700090000}, key, '
       'algorithm="HS256")\n',
       {"R10"}),

    # ----- R11: verify_iss False -----------------------------------------
    _s("r11_verify_iss_false",
       f'import jwt\njwt.decode(token, key, {_PIN}, '
       'options={"verify_iss": False})\n',
       {"R11"}),

    # ----- R12: excessive leeway -----------------------------------------
    _s("r12_excessive_leeway",
       f'import jwt\njwt.decode(token, key, {_PIN}, leeway=600)\n',
       {"R12"}),

    # ----- R13: verify_exp False -----------------------------------------
    _s("r13_verify_exp_false",
       f'import jwt\njwt.decode(token, key, {_PIN}, '
       'options={"verify_exp": False})\n',
       {"R13"}),

    # ----- R14: RSA/PEM key as string literal ----------------------------
    _s("r14_pem_string_key",
       'import jwt\nkey = "-----BEGIN PUBLIC KEY-----\\nMIIB\\n-----END PUBLIC KEY-----"\n'
       'jwt.decode(token, key, algorithms=["RS256"], audience="a", issuer="i")\n',
       {"R06", "R14"},
       note="PEM literal is both hardcoded (R06) and RSA-as-string (R14)"),

    # ----- R15: env secret + algorithms not pinned to one ----------------
    _s("r15_env_multi_alg",
       'import jwt\nimport os\nsecret = os.environ.get("K")\n'
       'jwt.decode(token, secret, algorithms=["HS256", "HS384"], '
       'audience="a", issuer="i")\n',
       {"R15"},
       note="env key + 2 HMAC algorithms (not single)"),

    # =====================================================================
    # SAFE samples — must produce zero findings
    # =====================================================================
    _s("safe_correct_usage",
       'import jwt\nimport os\n'
       'payload = {"sub": "u", "exp": 1700000000, "iat": 1699913600, '
       '"aud": "myapp", "iss": "auth"}\n'
       'token = jwt.encode(payload, os.environ["S"], algorithm="HS256")\n'
       'decoded = jwt.decode(token, os.environ["S"], algorithms=["HS256"], '
       'audience="myapp", issuer="auth")\n',
       set(), category="safe"),

    _s("safe_bytes_decode",
       'def to_text(data):\n    return data.decode("utf-8")\n',
       set(), category="safe", note="bytes.decode, not jwt"),

    _s("safe_str_encode",
       'def to_bytes(text):\n    return text.encode("utf-8")\n',
       set(), category="safe", note="str.encode, not jwt"),

    _s("safe_no_jwt",
       'import json\ndef load(p):\n    return json.load(open(p))\n',
       set(), category="safe"),

    _s("safe_dynamic_algorithms",
       'import jwt\nALLOWED = ["HS256"]\n'
       'jwt.decode(token, key, algorithms=ALLOWED, audience="a", issuer="i")\n',
       set(), category="safe", note="algorithms pinned via constant"),

    _s("safe_single_hmac_env",
       'import jwt\nimport os\nsecret = os.environ["K"]\n'
       'jwt.decode(token, secret, algorithms=["HS256"], audience="a", issuer="i")\n',
       set(), category="safe", note="env key but single algorithm -> no R15"),

    _s("safe_short_lifetime",
       'import jwt\njwt.encode({"iat": 1700000000, "exp": 1700003600}, key, '
       'algorithm="HS256")\n',
       set(), category="safe", note="1-hour lifetime, has exp -> no R07/R10"),
]


def all_samples() -> List[Sample]:
    return SAMPLES
