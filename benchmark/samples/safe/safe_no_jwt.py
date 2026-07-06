# CORPUS SAMPLE: safe_no_jwt
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: 

import json
def load(p):
    return json.load(open(p))
