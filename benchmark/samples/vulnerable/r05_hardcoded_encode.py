# CORPUS SAMPLE: r05_hardcoded_encode
# CATEGORY: vulnerable
# EXPECTED RULES: ['R05']
# NOTE: 

import jwt
jwt.encode({"exp": 1700000000}, "mysecret", algorithm="HS256")
