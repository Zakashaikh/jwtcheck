# CORPUS SAMPLE: r14_pem_string_key
# CATEGORY: vulnerable
# EXPECTED RULES: ['R06', 'R14']
# NOTE: PEM literal is both hardcoded (R06) and RSA-as-string (R14)

import jwt
key = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
jwt.decode(token, key, algorithms=["RS256"], audience="a", issuer="i")
