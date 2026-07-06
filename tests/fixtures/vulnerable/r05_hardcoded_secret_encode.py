import jwt
token = jwt.encode({"sub": "u", "exp": 1700000000}, "mysecret", algorithm="HS256")  # R05
