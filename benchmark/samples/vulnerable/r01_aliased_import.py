# CORPUS SAMPLE: r01_aliased_import
# CATEGORY: vulnerable
# EXPECTED RULES: ['R01', 'R08', 'R09']
# NOTE: aliased import, no algorithms

import jwt as j
j.decode(token, key)
