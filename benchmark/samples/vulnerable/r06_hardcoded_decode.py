# CORPUS SAMPLE: r06_hardcoded_decode
# CATEGORY: vulnerable
# EXPECTED RULES: ['R06']
# NOTE: 

import jwt
jwt.decode(token, "mysecret", algorithms=["HS256"], audience="a", issuer="i")
