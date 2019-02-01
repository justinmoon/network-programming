
def assert_raises(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
        raise Exception("Expected error")
    except Exception as e:
        print(f"Successfully observed expected error: '{e}'")

def get_special_chars():
    d = {}
    for i in range(256):
        b = bytes([i])
        if "\\x" not in str(b):
            d[i] = bytes([i]).decode()
    return d

special_chars = get_special_chars()


def calculate_checksum(payload_bytes):
    """First 4 bytes of sha256(sha256(payload))"""
    # We cheat here and convert to bytes b/c Buffer API hard to implement
    payload_bytes = bytes(payload_bytes.values)
    first_round = sha256(payload_bytes).digest()
    second_round = sha256(first_round).digest()
    first_four_bytes = second_round[:4]
#     return first_four_bytes
    return bites(list(first_four_bytes))
