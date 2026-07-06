# CORPUS SAMPLE: safe_short_lifetime
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: 1-hour lifetime, has exp -> no R07/R10

import jwt
jwt.encode({"iat": 1700000000, "exp": 1700003600}, key, algorithm="HS256")
