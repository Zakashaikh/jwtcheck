import jwt
payload = {"sub": "user123", "name": "Alice"}  # no exp
token = jwt.encode(payload, secret, algorithm="HS256")  # R07
