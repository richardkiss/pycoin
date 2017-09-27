import hashlib
import hmac
import unittest

from pycoin.key.BIP32Node import BIP32Node

#################



class CrackSigTest(unittest.TestCase):
    pass


import struct

from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding import public_pair_to_sec, from_bytes_32, to_bytes_32
from pycoin.key.BIP32Node import BIP32Node


ORDER = secp256k1_generator.order()

def ascend_bip32(bip32_pub_node, secret_exponent, child):
    """
    Given a BIP32Node with public derivation child "child" with a known private key,
    return the secret exponent for the bip32_pub_node.
    """
    i_as_bytes = struct.pack(">l", child)
    sec = public_pair_to_sec(bip32_pub_node.public_pair(), compressed=True)
    data = sec + i_as_bytes
    I64 = hmac.HMAC(key=bip32_pub_node._chain_code, msg=data, digestmod=hashlib.sha512).digest()
    I_left_as_exponent = from_bytes_32(I64[:32])
    return (secret_exponent - I_left_as_exponent) % ORDER


def crack_bip32(bip32_pub_node, secret_exponent, path):
    paths = path.split("/")
    while len(paths):
        path = int(paths.pop())
        secret_exponent = ascend_bip32(bip32_pub_node.subkey_for_path("/".join(paths)), secret_exponent, path)
    return BIP32Node(bip32_pub_node._netcode, bip32_pub_node._chain_code, bip32_pub_node._depth,
                     bip32_pub_node._parent_fingerprint, bip32_pub_node._child_index, secret_exponent=secret_exponent)


class CrackBIP32Test(unittest.TestCase):
    def test_crack_bip32(self):
        bip32key = BIP32Node.from_master_secret(b"foo")
        bip32_pub = bip32key.public_copy()
        secret_exponent_p0_1_7_9 = bip32key.subkey_for_path("0/1/7/9").secret_exponent()

        cracked_bip32_node = crack_bip32(bip32_pub, secret_exponent_p0_1_7_9, "0/1/7/9")
        self.assertEqual(cracked_bip32_node.hwif(as_private=True), bip32key.hwif(as_private=True))

    def test_ascend_bip32(self):
        bip32key = BIP32Node.from_master_secret(b"foo")
        bip32_pub = bip32key.public_copy()
        secret_exponent_p9 = bip32key.subkey_for_path("9").secret_exponent()
        secret_exponent = ascend_bip32(bip32_pub, secret_exponent_p9, 9)
        self.assertEqual(secret_exponent, bip32key.secret_exponent())