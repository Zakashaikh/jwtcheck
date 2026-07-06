import jwt
key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
decoded = jwt.decode(token, key, algorithms=["RS256"], audience="a", issuer="i")  # R14
