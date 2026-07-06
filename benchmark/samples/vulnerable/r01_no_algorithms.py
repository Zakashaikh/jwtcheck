# CORPUS SAMPLE: r01_no_algorithms
# CATEGORY: vulnerable
# EXPECTED RULES: ['R01', 'R08', 'R09']
# NOTE: no algorithms, audience or issuer

import jwt
jwt.decode(token, key)
