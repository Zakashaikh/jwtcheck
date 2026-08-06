# CORPUS SAMPLE: r14_pem_string_key
# CATEGORY: vulnerable
# EXPECTED RULES: ['R14']
# NOTE: PEM public key inlined as a string literal (R14). R06 is deliberately not expected: a decode key is the public half of the pair, so reporting it as a hardcoded secret is a false positive, and R14 already covers the key-management concern.

import jwt
key = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
jwt.decode(token, key, algorithms=["RS256"], audience="a", issuer="i")
