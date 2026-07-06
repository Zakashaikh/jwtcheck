import jwt
import os

# Multiple deliberate JWT misuses for demonstration
def login(user):
    payload = {"sub": user, "role": "admin"}        # no exp -> R06
    return jwt.encode(payload, "hardcoded-secret", algorithm="HS256")  # R04 + R13

def verify(token):
    secret = os.environ.get("JWT_SECRET")
    return jwt.decode(token, secret)                # R02 + R14 + R15

def verify_none(token):
    return jwt.decode(token, "k", algorithms=["none"])  # R01 + R15
