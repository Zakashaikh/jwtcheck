import jwt
decoded = jwt.decode(token, "", algorithms=["none"])  # R02
