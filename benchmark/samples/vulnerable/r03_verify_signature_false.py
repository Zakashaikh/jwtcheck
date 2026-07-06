# CORPUS SAMPLE: r03_verify_signature_false
# CATEGORY: vulnerable
# EXPECTED RULES: ['R03']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", options={"verify_signature": False})
