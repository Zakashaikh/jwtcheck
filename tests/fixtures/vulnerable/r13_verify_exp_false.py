import jwt
decoded = jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", options={"verify_exp": False})  # R13
