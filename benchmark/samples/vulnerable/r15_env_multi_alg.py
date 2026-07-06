# CORPUS SAMPLE: r15_env_multi_alg
# CATEGORY: vulnerable
# EXPECTED RULES: ['R15']
# NOTE: env key + 2 HMAC algorithms (not single)

import jwt
import os
secret = os.environ.get("K")
jwt.decode(token, secret, algorithms=["HS256", "HS384"], audience="a", issuer="i")
