import jwt
decoded = jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", leeway=600)  # R12
