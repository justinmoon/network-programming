def replace_bytes(base, index, new_bytes):
    """Helper function for unittests"""
    prefix = base[:index]
    suffix = base[index+len(new_bytes):]
    return prefix + new_bytes + suffix