"""A deliberately insecure PyJWT example used to demonstrate `jwtcheck scan`.

Each call site below triggers specific rules; the comment names the rule(s)
JWTCheck actually raises (verified against the scanner output, not guessed).
"""

import jwt
import os


def issue_token(user):
    payload = {"sub": user, "role": "admin"}                 # no exp claim
    # R05 (hardcoded signing secret) + R07 (payload missing exp)
    return jwt.encode(payload, "hardcoded-secret", algorithm="HS256")


def verify_unpinned(token):
    secret = os.environ.get("JWT_SECRET")
    # R01 (no algorithms= -> the token header chooses the algorithm)
    # R08 (no audience) + R09 (no issuer)
    return jwt.decode(token, secret)


def verify_none(token):
    # R02 ('none' accepted) + R06 (hardcoded verification key)
    # R08 (no audience) + R09 (no issuer)
    return jwt.decode(token, "k", algorithms=["none"])
