# Annotated intbytes.py file

from typing import List, Tuple


def int_to_bytes(n: int) -> bytes:
    """Convert an integer to bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\0'


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to an integer."""
    return int.from_bytes(b, 'big')


def ints_to_bytes(ints: List[int]) -> bytes:
    """Convert a list of integers to bytes."""
    return b''.join(int_to_bytes(i) for i in ints)


def bytes_to_ints(b: bytes) -> List[int]:
    """Convert bytes back to a list of integers."""
    return [bytes_to_int(b[i:i+4]) for i in range(0, len(b), 4)]