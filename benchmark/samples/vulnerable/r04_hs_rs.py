# CORPUS SAMPLE: r04_hs_rs
# CATEGORY: vulnerable
# EXPECTED RULES: ['R04']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256", "RS256"], audience="a", issuer="i")
