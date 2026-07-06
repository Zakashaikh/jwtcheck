import jwt
decoded = jwt.decode(token, key, algorithms=["HS256", "RS256"], audience="a", issuer="i")  # R04
