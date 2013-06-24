
import hashlib
import hmac
import struct

from . import ecdsa

from .encoding import public_pair_to_sec, public_pair_from_sec, public_pair_to_bitcoin_address, secret_exponent_to_wif, ripemd160_sha, a2b_hashed_base58, b2a_hashed_base58, double_sha256, public_pair_to_ripemd160_sha_sec

VERSION_PAIRS = [
    (True, False, 0x0488ADE4),
    (False, False, 0x0488B21E),
    (True, True,  0x04358394),
    (False, True, 0x043587CF)
]

VERSION_LOOKUP = dict(((private, test), v.to_bytes(4, byteorder="big")) for private, test, v in VERSION_PAIRS)
VERSION_LOOKUP_REV = dict((v.to_bytes(4, byteorder="big"), (private, test)) for private, test, v in VERSION_PAIRS)

class Wallet(object):
    """
    This is a deterministic wallet that complies with BIP0032 https://en.bitcoin.it/wiki/BIP_0032
    """
    @classmethod
    def from_master_secret(class_, master_secret, is_test=False):
        I64 = hmac.HMAC(key=b"Bitcoin seed", msg=master_secret, digestmod=hashlib.sha512).digest()
        return class_(is_private=True, is_test=is_test, chain_code=I64[32:], private_key=I64[:32])

    @classmethod
    def from_wallet_key(class_, b58_str):
        data = a2b_hashed_base58(b58_str)
        if data is None:
            raise Exception("bad checksum")

        is_private, is_test = VERSION_LOOKUP_REV.get(data[:4])
        parent_fingerprint, child_number = struct.unpack(">4sL", data[5:13])

        d = dict(is_private=is_private, is_test=is_test, chain_code=data[13:45], depth=data[4], parent_fingerprint=parent_fingerprint, child_number=child_number)

        if is_private:
            if data[45] != 0:
                raise Exception("encoded wrong")
            d["private_key"] = data[46:]
        else:
            d["public_pair"] = public_pair_from_sec(data[45:])

        return class_(**d)

    def __init__(self, is_private, is_test, chain_code, depth=0, parent_fingerprint=bytes([0]*4), child_number=0, private_key=None, public_pair=None):
        if is_private:
            if public_pair:
                raise Exception("can't include public_pair for private key")
        elif private_key:
            raise Exception("can't include private_key for public key")
        self.is_private = is_private
        self.is_test = is_test
        if is_private:
            if len(private_key) != 32:
                raise Exception("private key encoding wrong length")
            self.private_key = private_key
            self.exponent = int.from_bytes(self.private_key, byteorder="big")
            self.public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, self.exponent)
        else:
            # TODO: validate public_pair is on the curve
            self.public_pair = public_pair
        if len(chain_code) != 32:
            raise Exception("chain code wrong length")
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number

    def serialize(self, is_private=None):
        if is_private is None:
            if not self.is_private:
                raise Exception("public key has no private parts")
            is_private = self.is_private
        ba = bytearray(VERSION_LOOKUP[(is_private, self.is_test)])
        ba += bytes([self.depth]) + self.parent_fingerprint + struct.pack(">L", self.child_number) + self.chain_code
        if is_private:
            ba += bytes([0]) + self.private_key
        else:
            ba += public_pair_to_sec(self.public_pair, compressed=True)
        return bytes(ba)

    def fingerprint(self):
        return public_pair_to_ripemd160_sha_sec(self.public_pair, compressed=True)[:4]

    def wallet_key(self, is_private=False):
        return b2a_hashed_base58(self.serialize(is_private=is_private))

    def wif(self, compressed=True):
        if not self.is_private:
            raise Exception("not private")
        return secret_exponent_to_wif(self.exponent, compressed=compressed)

    def bitcoin_address(self, compressed=True):
        return public_pair_to_bitcoin_address(self.public_pair, compressed=compressed)

    def public_copy(self):
        return self.__class__(is_private=False, is_test=self.is_test, chain_code=self.chain_code, depth=self.depth, parent_fingerprint=self.parent_fingerprint, child_number=self.child_number, public_pair=self.public_pair)

    def subkey(self, i=0, is_prime=False, is_private=None):
        if is_private is None:
            is_private = self.is_private
        i &= 0x7fffffff
        if is_prime:
            i |= 0x80000000
        i_as_bytes = struct.pack(">L", i)
        if is_prime:
            if not self.is_private:
                raise Exception("can't derive a private key from a public key")
            data = bytes([0]) + self.private_key + i_as_bytes
        else:
            data = public_pair_to_sec(self.public_pair, compressed=True) + i_as_bytes
        I64 = hmac.HMAC(key=self.chain_code, msg=data, digestmod=hashlib.sha512).digest()
        I_left_as_exponent = int.from_bytes(I64[:32], byteorder="big")
        d = dict(is_private=is_private, is_test=self.is_test, chain_code=I64[32:], depth=self.depth+1, parent_fingerprint=self.fingerprint(), child_number=i)

        if is_private:
            exponent = (I_left_as_exponent + self.exponent) % ecdsa.generator_secp256k1.order()
            d["private_key"] = exponent.to_bytes(32, byteorder="big")
        else:
            x, y = self.public_pair
            the_point = I_left_as_exponent * ecdsa.generator_secp256k1 + ecdsa.Point(ecdsa.generator_secp256k1.curve(), x, y, ecdsa.generator_secp256k1.order())
            d["public_pair"] = the_point.pair()
        return self.__class__(**d)

    def repr(self):
        if self.child_number == 0:
            r = self.wallet_key()
        else:
            r = self.bitcoin_address()
        if self.is_private:
            return "PK<%s>" % r
        return "<%s>" % r
