# CORPUS SAMPLE: r12_excessive_leeway
# CATEGORY: vulnerable
# EXPECTED RULES: ['R12']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], audience="a", issuer="i", leeway=600)
