# CORPUS SAMPLE: r11_verify_iss_false
# CATEGORY: vulnerable
# EXPECTED RULES: ['R11']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", options={"verify_iss": False})
