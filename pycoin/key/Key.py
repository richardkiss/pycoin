from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding import EncodingError, a2b_hashed_base58, \
    from_bytes_32, hash160, hash160_sec_to_bitcoin_address, \
    is_sec_compressed, public_pair_to_sec, public_pair_to_hash160_sec, \
    sec_to_public_pair, secret_exponent_to_wif
from pycoin.key.validate import netcode_and_type_for_data
from pycoin.networks import address_prefix_for_netcode, wif_prefix_for_netcode, \
  pay_to_script_wit_for_netcode, pay_to_script_prefix_for_netcode, \
  address_wit_for_netcode
from pycoin.networks.default import get_current_netcode
from pycoin.serialize import b2h
from pycoin.tx.script.der import sigencode_der, sigdecode_der
from  pycoin.tx.pay_to.ScriptPayToAddressWit import ScriptPayToAddressWit


class InvalidPublicPairError(ValueError):
    pass


class InvalidSecretExponentError(ValueError):
    pass


class Key(object):
    def __init__(self, secret_exponent=None, public_pair=None, hash160=None,
                 prefer_uncompressed=None, is_compressed=None, is_pay_to_script=False, netcode=None):
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

        if is_compressed is None:
            is_compressed = False if hash160 else True
        if netcode is None:
            netcode = get_current_netcode()
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

        if self._public_pair is None and self._secret_exponent is not None:
            if self._secret_exponent < 1 \
                    or self._secret_exponent >= secp256k1_generator.order():
                raise InvalidSecretExponentError()
            public_pair = self._secret_exponent * secp256k1_generator
            self._public_pair = public_pair

        if self._public_pair is not None \
                and (None in self._public_pair or
                     not secp256k1_generator.contains_point(*self._public_pair)):
            raise InvalidPublicPairError()

    @classmethod
    def from_text(class_, text, is_compressed=False):
        """
        This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

        The "is_compressed" parameter is ignored unless a public address is passed in.
        """

        data = a2b_hashed_base58(text)
        netcode, key_type, length = netcode_and_type_for_data(data)
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
    def from_sec(class_, sec, netcode=None):
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
        return self._public_pair

    def netcode(self):
        """
        Return the netcode
        """
        return self._netcode

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
        hash_160 = self.hash160(use_uncompressed=use_uncompressed)
        if hash_160:
            is_p2pwk = address_wit_for_netcode(self._netcode)
            if is_p2pwk:
                witness = ScriptPayToAddressWit('\0', hash_160)
                return witness.info()['address_f']()
            is_p2pwk_in_p2sh = pay_to_script_wit_for_netcode(self._netcode)
            if is_p2pwk_in_p2sh:
                address_prefix = pay_to_script_prefix_for_netcode(self._netcode)
                wit_script = ScriptPayToAddressWit('\0', hash_160).script()
                hash_160 = hash160(wit_script)
            else:
                address_prefix = address_prefix_for_netcode(self._netcode)
            return hash160_sec_to_bitcoin_address(hash_160, address_prefix=address_prefix)
        return None

    bitcoin_address = address

    def as_text(self):
        """
        Return a textual representation of this key.
        """
        if self.secret_exponent():
            return self.wif()
        sec_hex = self.sec_as_hex()
        if sec_hex:
            return sec_hex
        return self.address()

    def public_copy(self):
        if self.secret_exponent() is None:
            return self

        return Key(public_pair=self.public_pair(), prefer_uncompressed=self._prefer_uncompressed,
                   is_compressed=(self._hash160_compressed is not None), netcode=self._netcode)

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

    def sign(self, h):
        """
        Return a der-encoded signature for a hash h.
        Will throw a RuntimeError if this key is not a private key
        """
        if not self.is_private():
            raise RuntimeError("Key must be private to be able to sign")
        val = from_bytes_32(h)
        r, s = secp256k1_generator.sign(self.secret_exponent(), val)
        return sigencode_der(r, s)

    def verify(self, h, sig):
        """
        Return whether a signature is valid for hash h using this key.
        """
        val = from_bytes_32(h)
        pubkey = self.public_pair()
        rs = sigdecode_der(sig)
        if self.public_pair() is None:
            # find the pubkey from the signature and see if it matches
            # our key
            possible_pubkeys = secp256k1_generator.possible_public_pairs_for_signature(val, rs)
            hash160 = self.hash160()
            for candidate in possible_pubkeys:
                if hash160 == public_pair_to_hash160_sec(candidate, True):
                    pubkey = candidate
                    break
                if hash160 == public_pair_to_hash160_sec(candidate, False):
                    pubkey = candidate
                    break
            else:
                # signature is using a pubkey that's not this key
                return False
        return secp256k1_generator.verify(pubkey, val, rs)

    def _use_uncompressed(self, use_uncompressed=None):
        if use_uncompressed:
            return use_uncompressed
        if use_uncompressed is None:
            return self._prefer_uncompressed
        return False

    def __repr__(self):
        r = self.public_copy().as_text()
        if self.is_private():
            return "private_for <%s>" % r
        return "<%s>" % r
