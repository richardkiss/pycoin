from __future__ import annotations

import hmac
import hashlib
import struct
from typing import Any

from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.encoding.sec import public_pair_to_sec


def ascend_bip32(bip32_pub_node: Any, secret_exponent: int, child: int) -> int:
    """
    Given a BIP32Node with public derivation child "child" with a known private key,
    return the secret exponent for the bip32_pub_node.
    """
    i_as_bytes = struct.pack(">l", child)
    sec = public_pair_to_sec(bip32_pub_node.public_pair(), compressed=True)
    data = sec + i_as_bytes
    I64 = hmac.HMAC(
        key=bip32_pub_node._chain_code, msg=data, digestmod=hashlib.sha512
    ).digest()
    I_left_as_exponent = from_bytes_32(I64[:32])
    return (secret_exponent - I_left_as_exponent) % bip32_pub_node._generator.order()  # type: ignore[no-any-return]


def crack_bip32(bip32_pub_node: Any, secret_exponent: int, path: str) -> Any:
    paths = path.split("/")
    while len(paths):
        child = int(paths.pop())
        secret_exponent = ascend_bip32(
            bip32_pub_node.subkey_for_path("/".join(paths)), secret_exponent, child
        )
    return bip32_pub_node.__class__(
        bip32_pub_node._chain_code,
        bip32_pub_node._depth,
        bip32_pub_node._parent_fingerprint,
        bip32_pub_node._child_index,
        secret_exponent=secret_exponent,
    )
