# CORPUS SAMPLE: r02_none_mixed
# CATEGORY: vulnerable
# EXPECTED RULES: ['R02']
# NOTE: none mixed with a real algorithm

import jwt
jwt.decode(token, key, algorithms=["HS256", "none"], audience="a", issuer="i")
