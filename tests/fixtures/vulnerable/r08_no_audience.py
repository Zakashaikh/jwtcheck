import jwt
decoded = jwt.decode(token, key, algorithms=["HS256"], issuer="i")  # R08
