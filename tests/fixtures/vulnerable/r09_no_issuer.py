import jwt
decoded = jwt.decode(token, key, algorithms=["HS256"], audience="a")  # R09
