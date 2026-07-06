# CORPUS SAMPLE: safe_correct_usage
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: 

import jwt
import os
payload = {"sub": "u", "exp": 1700000000, "iat": 1699913600, "aud": "myapp", "iss": "auth"}
token = jwt.encode(payload, os.environ["S"], algorithm="HS256")
decoded = jwt.decode(token, os.environ["S"], algorithms=["HS256"], audience="myapp", issuer="auth")
