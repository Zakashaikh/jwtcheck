# CORPUS SAMPLE: r09_no_issuer
# CATEGORY: vulnerable
# EXPECTED RULES: ['R09']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], audience="a")
