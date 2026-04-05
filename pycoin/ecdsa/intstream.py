from typing import Literal


def to_bytes(v: int, length: int, byteorder: Literal["little", "big"] = "big") -> bytes:
    """Same as ``int.to_bytes``."""
    return v.to_bytes(length, byteorder=byteorder)


def from_bytes(
    data: bytes, byteorder: Literal["little", "big"] = "big", signed: bool = False
) -> int:
    """Same as ``int.from_bytes``."""
    return int.from_bytes(data, byteorder=byteorder, signed=signed)
