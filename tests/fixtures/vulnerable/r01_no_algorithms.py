import jwt
decoded = jwt.decode(token, key)  # R01: no algorithms parameter
