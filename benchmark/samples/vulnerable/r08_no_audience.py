# CORPUS SAMPLE: r08_no_audience
# CATEGORY: vulnerable
# EXPECTED RULES: ['R08']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"], issuer="i")
