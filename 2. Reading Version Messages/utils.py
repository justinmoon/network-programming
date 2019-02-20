def replace_bytes(base, index, new_bytes):
    """Helper function for unittests"""
    prefix = base[:index]
    suffix = base[index+len(new_bytes):]
    return prefix + new_bytes + suffix

def assert_len(payload, field, expected_len):
    observed_len = len(payload[field])
    assert observed_len == expected_len,\
        f'The "{field}" field should be {expected_len} bytes, was {observed_len} bytes'

def check_field(payload, field, bytes_value, int_value):
    assert payload[field] == int_value,\
        f'Correct integer interpretation of {bytes_value} for field "{field}" is {int_value}, not {payload[field]}'
