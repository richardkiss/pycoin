import hashlib

from .subpaths import subpaths_for_path_range

from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.encoding.hash import double_sha256
from pycoin.key.Key import Key
from pycoin.serialize import b2h


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
    def __init__(self, generator, initial_key=None, master_private_key=None, public_pair=None, master_public_key=None):
        if [initial_key, public_pair, master_private_key, master_public_key].count(None) != 3:
            raise ValueError(
                "exactly one of initial_key, master_private_key, master_public_key must be non-None")
        self._initial_key = initial_key
        self._generator = generator

        if initial_key is not None:
            master_private_key = initial_key_to_master_key(initial_key)
        if master_public_key:
            public_pair = tuple(from_bytes_32(master_public_key[idx:idx+32]) for idx in (0, 32))
        super(ElectrumWallet, self).__init__(
            generator=generator, secret_exponent=master_private_key, public_pair=public_pair, prefer_uncompressed=True)

    def secret_exponent(self):
        if self._secret_exponent is None and self._initial_key:
            self._secret_exponent = initial_key_to_master_key(b2h(self._initial_key))
        return self._secret_exponent

    def master_private_key(self):
        return self.secret_exponent()

    def master_public_key(self):
        return self.sec(use_uncompressed=True)[1:]

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
        if self.secret_exponent():
            return self.__class__(
                generator=self._generator,
                master_private_key=((self.master_private_key() + offset) % self._generator.order())
            )
        p1 = offset * self._generator
        x, y = self.public_pair()
        p2 = self._generator.Point(x, y)
        p = p1 + p2
        return self.__class__(public_pair=p, generator=self._generator)

    def subkeys(self, path):
        """
        A generalized form that can return multiple subkeys.
        """
        for _ in subpaths_for_path_range(path, hardening_chars="'pH"):
            yield self.subkey(_)

    def __str__(self):
        return "Electrum<%s>" % b2h(self.master_public_key)
