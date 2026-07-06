# CORPUS SAMPLE: r10_inline_lifetime
# CATEGORY: vulnerable
# EXPECTED RULES: ['R10']
# NOTE: 

import jwt
jwt.encode({"iat": 1700000000, "exp": 1700090000}, key, algorithm="HS256")
