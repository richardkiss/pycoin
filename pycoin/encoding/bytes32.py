def to_bytes_32(v):
    return v.to_bytes(32, byteorder="big")


def from_bytes_32(v):
    return int.from_bytes(v, byteorder="big")
