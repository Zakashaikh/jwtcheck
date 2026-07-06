import jwt
payload = {"sub": "u", "iat": 1700000000, "exp": 1700200000}  # >24h apart
token = jwt.encode(payload, secret, algorithm="HS256")  # R10
