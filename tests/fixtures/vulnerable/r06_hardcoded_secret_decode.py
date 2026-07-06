import jwt
decoded = jwt.decode(token, "mysecret", algorithms=["HS256"], audience="a", issuer="i")  # R06
