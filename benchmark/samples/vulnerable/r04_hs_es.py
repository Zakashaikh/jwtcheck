# CORPUS SAMPLE: r04_hs_es
# CATEGORY: vulnerable
# EXPECTED RULES: ['R04']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS384", "ES256"], audience="a", issuer="i")
