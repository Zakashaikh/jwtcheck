import jwt
decoded = jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", options={"verify_signature": False})  # R03
