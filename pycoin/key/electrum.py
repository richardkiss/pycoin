import hashlib

from pycoin import ecdsa
from pycoin.encoding import double_sha256, from_bytes_32, to_bytes_32
from pycoin.key import Key


ORDER = ecdsa.generator_secp256k1.order()


def initial_key_to_master_key(initial_key):
    """
    initial_key:
        a hex string of length 32
    """
    b = initial_key.encode("utf8")
    orig_input = b
    for i in range(100000):
        b = hashlib.sha256(b + orig_input).digest()
    return from_bytes_32(b)


class ElectrumWallet(Key):
    def __init__(self, initial_key=None, master_private_key=None, master_public_key=None):
        if [initial_key, master_private_key, master_public_key].count(None) != 2:
            raise ValueError(
                "exactly one of initial_key, master_private_key, master_public_key must be non-None")
        self._initial_key = initial_key
        self._master_private_key = master_private_key
        self._master_public_key = master_public_key
        self._public_pair = None

    def master_private_key(self):
        if self._master_private_key is None and self._initial_key:
            self._master_private_key = initial_key_to_master_key(self._initial_key)
        return self._master_private_key

    def master_public_key(self):
        if self._master_public_key is None:
            self._public_pair = ecdsa.public_pair_for_secret_exponent(
                ecdsa.generator_secp256k1, self.master_private_key())
            self._master_public_key = to_bytes_32(self._public_pair[0]) + to_bytes_32(self._public_pair[1])
        return self._master_public_key

    def public_pair(self):
        if self._public_pair is None:
            mpk = self.master_public_key()
            self._public_pair = tuple(from_bytes_32(mpk[idx:idx+32]) for idx in (0, 32))
        return self._public_pair

    def subkey(self, path):
        """
        path:
            of the form "K" where K is an integer index, or "K/N" where N is usually
            a 0 (deposit address) or 1 (change address)
        """
        t = path.split("/")
        if len(t) == 2:
            n, for_change = t
        else:
            n, = t
            for_change = 0
        b = (str(n) + ':' + str(for_change) + ':').encode("utf8") + self.master_public_key()
        offset = from_bytes_32(double_sha256(b))
        if self._master_private_key:
            return Key(
                secret_exponent=((self._master_private_key + offset) % ORDER),
                prefer_uncompressed=True
            )
        p1 = offset * ecdsa.generator_secp256k1
        x, y = self.public_pair()
        p2 = ecdsa.Point(ecdsa.generator_secp256k1.curve(), x, y, ORDER)
        p = p1 + p2
        return Key(public_pair=p.pair(), prefer_uncompressed=True)

    def __str__(self):
        return self.master_public_key
