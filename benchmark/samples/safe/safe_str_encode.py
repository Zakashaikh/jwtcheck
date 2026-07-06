# CORPUS SAMPLE: safe_str_encode
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: str.encode, not jwt

def to_bytes(text):
    return text.encode("utf-8")
