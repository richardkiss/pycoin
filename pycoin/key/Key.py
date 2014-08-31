from pycoin import ecdsa
from pycoin.key.validate import netcode_and_type_for_data
from pycoin.networks import address_prefix_for_netcode, wif_prefix_for_netcode

from pycoin.encoding import a2b_hashed_base58, secret_exponent_to_wif,\
    public_pair_to_sec, hash160,\
    hash160_sec_to_bitcoin_address, sec_to_public_pair,\
    is_sec_compressed, from_bytes_32, EncodingError
from pycoin.serialize import b2h


class InvalidKeyGeneratedError(Exception):
    pass


class Key(object):
    def __init__(self, secret_exponent=None, public_pair=None, hash160=None,
                 prefer_uncompressed=None, is_compressed=True, is_pay_to_script=False, netcode='BTC'):
        """
        secret_exponent:
            a long representing the secret exponent
        public_pair:
            a tuple of long integers on the ecdsa curve
        hash160:
            a hash160 value corresponding to a bitcoin address

        Include at most one of secret_exponent, public_pair or hash160.

        prefer_uncompressed:
            whether or not to produce text outputs as compressed or uncompressed.

        is_pay_to_script:
            whether or not this key is for a pay-to-script style transaction

        netcode:
            the code for the network (as defined in pycoin.networks)

        Include at most one of secret_exponent, public_pair or hash160.
        prefer_uncompressed, is_compressed (booleans) are optional.
        """

        if [secret_exponent, public_pair, hash160].count(None) != 2:
            raise ValueError("exactly one of secret_exponent, public_pair, hash160 must be passed.")
        if prefer_uncompressed is None:
            prefer_uncompressed = not is_compressed
        self._prefer_uncompressed = prefer_uncompressed
        self._secret_exponent = secret_exponent
        self._public_pair = public_pair
        self._hash160_uncompressed = None
        self._hash160_compressed = None
        if hash160:
            if is_compressed:
                self._hash160_compressed = hash160
            else:
                self._hash160_uncompressed = hash160
        self._netcode = netcode

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
            # TODO: fix this... it doesn't belong here
            from pycoin.key.BIP32Node import BIP32Node
            return BIP32Node.from_wallet_key(text)

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
    def from_sec(class_, sec, netcode="BTC"):
        """
        Create a key from an sec bytestream (which is an encoding of a public pair).
        """
        public_pair = sec_to_public_pair(sec)
        return class_(public_pair=public_pair, is_compressed=is_sec_compressed(sec), netcode=netcode)

    def is_private(self):
        return self.secret_exponent() is not None

    def secret_exponent(self):
        """
        Return an integer representing the secret exponent (or None).
        """
        return self._secret_exponent

    def wif(self, use_uncompressed=None):
        """
        Return the WIF representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        wif_prefix = wif_prefix_for_netcode(self._netcode)
        secret_exponent = self.secret_exponent()
        if secret_exponent is None:
            return None
        return secret_exponent_to_wif(secret_exponent,
                                      compressed=not self._use_uncompressed(use_uncompressed),
                                      wif_prefix=wif_prefix)

    def public_pair(self):
        """
        Return a pair of integers representing the public key (or None).
        """
        if self._public_pair is None and self.secret_exponent():
            public_pair = ecdsa.public_pair_for_secret_exponent(
                ecdsa.generator_secp256k1, self._secret_exponent)
            if not ecdsa.is_public_pair_valid(ecdsa.generator_secp256k1, public_pair):
                raise InvalidKeyGeneratedError(
                    "this key would produce an invalid public pair; please skip it")
            self._public_pair = public_pair

        return self._public_pair

    def sec(self, use_uncompressed=None):
        """
        Return the SEC representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        public_pair = self.public_pair()
        if public_pair is None:
            return None
        return public_pair_to_sec(public_pair, compressed=not self._use_uncompressed(use_uncompressed))

    def sec_as_hex(self, use_uncompressed=None):
        """
        Return the SEC representation of this key as hex text.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        sec = self.sec(use_uncompressed=use_uncompressed)
        if sec is None:
            return None
        return b2h(sec)

    def hash160(self, use_uncompressed=None):
        """
        Return the hash160 representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        use_uncompressed = self._use_uncompressed(use_uncompressed)
        if self.public_pair() is None:
            if use_uncompressed:
                return self._hash160_uncompressed
            return self._hash160_compressed

        if use_uncompressed:
            if self._hash160_uncompressed is None:
                self._hash160_uncompressed = hash160(self.sec(use_uncompressed=use_uncompressed))
            return self._hash160_uncompressed

        if self._hash160_compressed is None:
            self._hash160_compressed = hash160(self.sec(use_uncompressed=use_uncompressed))
        return self._hash160_compressed

    def address(self, use_uncompressed=None):
        """
        Return the public address representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        address_prefix = address_prefix_for_netcode(self._netcode)
        hash160 = self.hash160(use_uncompressed=use_uncompressed)
        if hash160:
            return hash160_sec_to_bitcoin_address(hash160, address_prefix=address_prefix)
        return None

    bitcoin_address = address

    def as_text(self):
        """
        Return a textual representation of this key.
        """
        if self.secret_exponent():
            return self.wif()
        sec_hex = self.sec_as_hex()
        if pp:
            return pp
        return self.address()

    def public_copy(self):
        if self.secret_exponent() is None:
            return self
        return Key(public_pair=self.public_pair(), prefer_uncompressed=self._prefer_uncompressed,
                   is_compressed=self._is_compressed, netcode=self._netcode)

    def subkey(self, path_to_subkey):
        """
        Return the Key corresponding to the hierarchical wallet's subkey
        """
        return self

    def subkeys(self, path_to_subkeys):
        """
        Return an iterator yielding Keys corresponding to the
        hierarchical wallet's subkey path (or just this key).
        """
        yield self

    def _use_uncompressed(self, use_uncompressed=None):
        if use_uncompressed:
            return use_uncompressed
        if use_uncompressed is None:
            return self._prefer_uncompressed
        return False

    def __repr__(self):
        r = self.public_copy().as_text()
        if self.is_private:
            return "private_for <%s>" % r
        return "<%s>" % r
