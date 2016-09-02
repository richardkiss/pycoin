import hashlib
import itertools

from pycoin import ecdsa
from pycoin.encoding import double_sha256, from_bytes_32, to_bytes_32
from pycoin.key import Key
from pycoin.serialize import b2h

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
    def __init__(self, initial_key=None, master_private_key=None, master_public_key=None, netcode='BTC'):
        if [initial_key, master_private_key, master_public_key].count(None) != 2:
            raise ValueError(
                "exactly one of initial_key, master_private_key, master_public_key must be non-None")
        self._initial_key = initial_key
        self._netcode = netcode

        if initial_key is not None:
            master_private_key = initial_key_to_master_key(initial_key)
        pp = None
        if master_public_key:
            pp = tuple(from_bytes_32(master_public_key[idx:idx+32]) for idx in (0, 32))
        super(ElectrumWallet, self).__init__(secret_exponent=master_private_key, public_pair=pp)
        self._master_public_key = None

    def secret_exponent(self):
        if self._secret_exponent is None and self._initial_key:
            self._secret_exponent = initial_key_to_master_key(b2h(self._initial_key))
        return self._secret_exponent

    def master_private_key(self):
        return self.secret_exponent()

    def master_public_key(self):
        if self._master_public_key is None:
            pp = self.public_pair()
            self._master_public_key = to_bytes_32(pp[0]) + to_bytes_32(pp[1])
        return self._master_public_key

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
        if self.master_private_key():
            return Key(
                secret_exponent=((self.master_private_key() + offset) % ORDER),
                prefer_uncompressed=True
            )
        p1 = offset * ecdsa.generator_secp256k1
        x, y = self.public_pair()
        p2 = ecdsa.Point(ecdsa.generator_secp256k1.curve(), x, y, ORDER)
        p = p1 + p2
        return Key(public_pair=p.pair(), prefer_uncompressed=True)

    def subkeys(self, path):
        """
        A generalized form that can return multiple subkeys.
        """
        if path == '':
            yield self
            return

        def range_iterator(the_range):
            for r in the_range.split(","):
                is_hardened = r[-1] in "'pH"
                if is_hardened:
                    r = r[:-1]
                hardened_char = "H" if is_hardened else ''
                if '-' in r:
                    low, high = [int(x) for x in r.split("-", 1)]
                    for t in range(low, high+1):
                        yield "%d%s" % (t, hardened_char)
                else:
                    yield "%s%s" % (r, hardened_char)

        def subkey_iterator(subkey_paths):
            # examples:
            #   0/1H/0-4 => ['0/1H/0', '0/1H/1', '0/1H/2', '0/1H/3', '0/1H/4']
            #   0/2,5,9-11 => ['0/2', '0/5', '0/9', '0/10', '0/11']
            #   3H/2/5/15-20p => ['3H/2/5/15p', '3H/2/5/16p', '3H/2/5/17p', '3H/2/5/18p',
            #          '3H/2/5/19p', '3H/2/5/20p']
            #   5-6/7-8p,15/1-2 => ['5/7H/1', '5/7H/2', '5/8H/1', '5/8H/2',
            #         '5/15/1', '5/15/2', '6/7H/1', '6/7H/2', '6/8H/1', '6/8H/2', '6/15/1', '6/15/2']

            components = subkey_paths.split("/")
            iterators = [range_iterator(c) for c in components]
            for v in itertools.product(*iterators):
                yield '/'.join(v)

        for subkey in subkey_iterator(path):
            yield self.subkey(subkey)

    def __str__(self):
        return "Electrum<%s>" % b2h(self.master_public_key)
