from typing import Literal


def to_bytes(v: int, length: int, byteorder: Literal["big", "little"] = "big") -> bytes:
    """This is the same functionality as ``int.to_bytes`` in python 3"""
    return v.to_bytes(length, byteorder=byteorder)


def from_bytes(bytes: bytes, byteorder: Literal["big", "little"] = "big", signed: bool = False) -> int:
    """This is the same functionality as ``int.from_bytes`` in python 3"""
    return int.from_bytes(bytes, byteorder=byteorder, signed=signed)
