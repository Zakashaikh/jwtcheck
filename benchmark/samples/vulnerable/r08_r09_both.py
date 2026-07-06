# CORPUS SAMPLE: r08_r09_both
# CATEGORY: vulnerable
# EXPECTED RULES: ['R08', 'R09']
# NOTE: 

import jwt
jwt.decode(token, key, algorithms=["HS256"])
