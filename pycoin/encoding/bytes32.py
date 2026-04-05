def to_bytes_32(v: int) -> bytes:
    return v.to_bytes(32, byteorder="big")


def from_bytes_32(v: bytes) -> int:
    return int.from_bytes(v, byteorder="big")
