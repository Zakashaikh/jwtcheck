# CORPUS SAMPLE: r13_verify_exp_false
# CATEGORY: vulnerable
# EXPECTED RULES: ['R13']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", options={"verify_exp": False})
