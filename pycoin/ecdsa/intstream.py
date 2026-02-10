

def to_bytes(v, length, byteorder="big"):
    """This is the same functionality as ``int.to_bytes`` in python 3"""
    return v.to_bytes(length, byteorder=byteorder)


def from_bytes(bytes, byteorder="big", signed=False):
    """This is the same functionality as ``int.from_bytes`` in python 3"""
    return int.from_bytes(bytes, byteorder=byteorder, signed=signed)
