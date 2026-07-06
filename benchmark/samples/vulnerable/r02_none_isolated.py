# CORPUS SAMPLE: r02_none_isolated
# CATEGORY: vulnerable
# EXPECTED RULES: ['R02']
# NOTE: algorithms=['none'] isolated

import jwt
jwt.decode(token, key, algorithms=["none"], audience="a", issuer="i")
