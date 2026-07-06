import jwt
import os
secret = os.environ.get("JWT_SECRET")
decoded = jwt.decode(token, secret, algorithms=["HS256", "RS256"], audience="a", issuer="i")  # R15
