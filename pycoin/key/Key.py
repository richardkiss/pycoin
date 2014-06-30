from pycoin import ecdsa
from pycoin.key.validate import netcode_and_type_for_data
from pycoin.networks import address_prefix_for_netcode, wif_prefix_for_netcode

from pycoin.encoding import a2b_hashed_base58, secret_exponent_to_wif,\
    public_pair_to_sec, hash160,\
    hash160_sec_to_bitcoin_address, sec_to_public_pair,\
    is_sec_compressed, from_bytes_32, EncodingError

from .bip32 import Wallet


class Key(object):
    def __init__(self, hierarchical_wallet=None, secret_exponent=None, public_pair=None, hash160=None,
                 prefer_uncompressed=None, is_compressed=True, netcode='BTC'):
        """
        hierarchical_wallet:
            a bip32 wallet
        secret_exponent:
            a long representing the secret exponent
        public_pair:
            a tuple of long integers on the ecdsa curve
        hash160:
            a hash160 value corresponding to a bitcoin address
        Include at most one of hierarchical_wallet, secret_exponent, public_pair or hash160.
        prefer_uncompressed, is_compressed (booleans) are optional.
        netcode:
            the code for the network (as defined in pycoin.networks)
        """
        if [hierarchical_wallet, secret_exponent, public_pair, hash160].count(None) != 3:
            raise ValueError("exactly one of hierarchical_wallet, secret_exponent, public_pair, hash160"
                             " must be passed.")
        if prefer_uncompressed is None:
            prefer_uncompressed = not is_compressed
        self._prefer_uncompressed = prefer_uncompressed
        self._hierarchical_wallet = hierarchical_wallet
        self._secret_exponent = secret_exponent
        self._public_pair = public_pair
        if hash160:
            if is_compressed:
                self._hash160_compressed = hash160
            else:
                self._hash160_uncompressed = hash160
        self._netcode = netcode
        self._calculate_all()

    @classmethod
    def from_text(class_, text, is_compressed=True):
        """
        This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

        The "is_compressed" parameter is ignored unless a public address is passed in.
        """

        data = a2b_hashed_base58(text)
        netcode, key_type = netcode_and_type_for_data(data)
        data = data[1:]

        if key_type in ("pub32", "prv32"):
            hw = Wallet.from_wallet_key(text)
            return Key(hierarchical_wallet=hw, netcode=netcode)

        if key_type == 'wif':
            is_compressed = (len(data) > 32)
            if is_compressed:
                data = data[:-1]
            return Key(
                secret_exponent=from_bytes_32(data),
                prefer_uncompressed=not is_compressed, netcode=netcode)
        if key_type == 'address':
            return Key(hash160=data, is_compressed=is_compressed, netcode=netcode)
        raise EncodingError("unknown text: %s" % text)

    @classmethod
    def from_sec(class_, sec):
        """
        Create a key from an sec bytestream (which is an encoding of a public pair).
        """
        public_pair = sec_to_public_pair(sec)
        return Key(public_pair=public_pair, prefer_uncompressed=not is_sec_compressed(sec))

    def public_copy(self):
        """
        Create a copy of this key with private key information removed.
        """
        if self._hierarchical_wallet:
            return Key(hierarchical_wallet=self._hierarchical_wallet.public_copy())
        if self.public_pair():
            return Key(public_pair=self.public_pair())
        return self

    def _calculate_all(self):
        for attr in "_secret_exponent _public_pair _wif_uncompressed _wif_compressed _sec_compressed" \
                " _sec_uncompressed _hash160_compressed _hash160_uncompressed _address_compressed" \
                " _address_uncompressed _netcode".split():
                setattr(self, attr, getattr(self, attr, None))

        if self._hierarchical_wallet:
            if self._hierarchical_wallet.is_private:
                self._secret_exponent = self._hierarchical_wallet.secret_exponent
            else:
                self._public_pair = self._hierarchical_wallet.public_pair
            self._netcode = self._hierarchical_wallet.netcode

        wif_prefix = wif_prefix_for_netcode(self._netcode)

        if self._secret_exponent:
            self._wif_uncompressed = secret_exponent_to_wif(
                self._secret_exponent, compressed=False, wif_prefix=wif_prefix)
            self._wif_compressed = secret_exponent_to_wif(
                self._secret_exponent, compressed=True, wif_prefix=wif_prefix)
            self._public_pair = ecdsa.public_pair_for_secret_exponent(
                ecdsa.generator_secp256k1, self._secret_exponent)

        if self._public_pair:
            self._sec_compressed = public_pair_to_sec(self._public_pair, compressed=True)
            self._sec_uncompressed = public_pair_to_sec(self._public_pair, compressed=False)
            self._hash160_compressed = hash160(self._sec_compressed)
            self._hash160_uncompressed = hash160(self._sec_uncompressed)

        address_prefix = address_prefix_for_netcode(self._netcode)

        if self._hash160_compressed:
            self._address_compressed = hash160_sec_to_bitcoin_address(
                self._hash160_compressed, address_prefix=address_prefix)

        if self._hash160_uncompressed:
            self._address_uncompressed = hash160_sec_to_bitcoin_address(
                self._hash160_uncompressed, address_prefix=address_prefix)

    def as_text(self):
        """
        Return a textual representation of this key.
        """
        if self._hierarchical_wallet:
            return self._hierarchical_wallet.wallet_key(as_private=self._hierarchical_wallet.is_private)
        if self._secret_exponent:
            return self.wif()
        return self.address()

    def hierarchical_wallet(self):
        return self._hierarchical_wallet

    def hwif(self, as_private=False):
        """
        Return a textual representation of the hiearachical wallet (reduced to public), or None.
        """
        if self._hierarchical_wallet:
            return self._hierarchical_wallet.wallet_key(as_private=as_private)
        return None

    def secret_exponent(self):
        """
        Return an integer representing the secret exponent (or None).
        """
        return self._secret_exponent

    def public_pair(self):
        """
        Return a pair of integers representing the public key (or None).
        """
        return self._public_pair

    def _use_uncompressed(self, use_uncompressed):
        if use_uncompressed:
            return use_uncompressed
        if use_uncompressed is None:
            return self._prefer_uncompressed
        return False

    def wif(self, use_uncompressed=None):
        """
        Return the WIF representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._wif_uncompressed
        return self._wif_compressed

    def sec(self, use_uncompressed=None):
        """
        Return the SEC representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._sec_uncompressed
        return self._sec_compressed

    def hash160(self, use_uncompressed=None):
        """
        Return the hash160 representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._hash160_uncompressed
        return self._hash160_compressed

    def address(self, use_uncompressed=None):
        """
        Return the public address representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._address_uncompressed
        return self._address_compressed

    def subkey(self, path_to_subkey):
        """
        Return the Key corresponding to the hierarchical wallet's subkey (or None).
        """
        if self._hierarchical_wallet:
            return Key(hierarchical_wallet=self._hierarchical_wallet.subkey_for_path(str(path_to_subkey)))

    def subkeys(self, path_to_subkeys):
        """
        Return an iterator yielding Keys corresponding to the
        hierarchical wallet's subkey path (or just this key).
        """
        if self._hierarchical_wallet:
            for subwallet in self._hierarchical_wallet.subkeys_for_path(path_to_subkeys):
                yield Key(hierarchical_wallet=subwallet)
        else:
            yield self
