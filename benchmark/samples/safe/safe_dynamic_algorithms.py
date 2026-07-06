# CORPUS SAMPLE: safe_dynamic_algorithms
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: algorithms pinned via constant

import jwt
ALLOWED = ["HS256"]
jwt.decode(token, key, algorithms=ALLOWED, audience="a", issuer="i")
