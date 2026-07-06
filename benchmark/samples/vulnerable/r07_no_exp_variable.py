# CORPUS SAMPLE: r07_no_exp_variable
# CATEGORY: vulnerable
# EXPECTED RULES: ['R07']
# NOTE: variable-resolved payload (hard case)

import jwt
payload = {"sub": "u"}
jwt.encode(payload, key, algorithm="HS256")
