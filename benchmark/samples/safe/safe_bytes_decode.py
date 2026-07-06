# CORPUS SAMPLE: safe_bytes_decode
# CATEGORY: safe
# EXPECTED RULES: NONE
# NOTE: bytes.decode, not jwt

def to_text(data):
    return data.decode("utf-8")
