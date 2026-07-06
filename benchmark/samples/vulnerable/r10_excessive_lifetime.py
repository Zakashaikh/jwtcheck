# CORPUS SAMPLE: r10_excessive_lifetime
# CATEGORY: vulnerable
# EXPECTED RULES: ['R10']
# NOTE: exp - iat = 200000s > 86400

import jwt
payload = {"iat": 1700000000, "exp": 1700200000}
jwt.encode(payload, key, algorithm="HS256")
