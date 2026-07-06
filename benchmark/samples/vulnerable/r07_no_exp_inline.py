# CORPUS SAMPLE: r07_no_exp_inline
# CATEGORY: vulnerable
# EXPECTED RULES: ['R07']
# NOTE: 

import jwt
jwt.encode({"sub": "u"}, key, algorithm="HS256")
