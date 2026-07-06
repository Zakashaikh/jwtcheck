# CORPUS SAMPLE: safe_single_hmac_env
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: env key but single algorithm -> no R15

import jwt
import os
secret = os.environ["K"]
jwt.decode(token, secret, algorithms=["HS256"], audience="a", issuer="i")
