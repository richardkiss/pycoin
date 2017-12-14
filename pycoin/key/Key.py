from pycoin.encoding.hash import hash160
from pycoin.encoding.bytes32 import from_bytes_32, to_bytes_32
from pycoin.encoding.sec import (
    is_sec_compressed, public_pair_to_sec,
    public_pair_to_hash160_sec, sec_to_public_pair
)
from pycoin.serialize import b2h
from pycoin.satoshi.der import sigencode_der, sigdecode_der


class InvalidPublicPairError(ValueError):
    pass


class InvalidSecretExponentError(ValueError):
    pass


class Key(object):

    _default_ui_context = None

    @classmethod
    def make_subclass(class_, default_ui_context):

        class Key(class_):
            pass

        Key._default_ui_context = default_ui_context
        return Key

    def __init__(self, secret_exponent=None, generator=None, public_pair=None, hash160=None, prefer_uncompressed=None,
                 is_compressed=None, is_pay_to_script=False):
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

        Include at most one of secret_exponent, public_pair or hash160.
        prefer_uncompressed, is_compressed (booleans) are optional.
        """
        if [secret_exponent, public_pair, hash160].count(None) != 2:
            raise ValueError("exactly one of secret_exponent, public_pair, hash160 must be passed.")
        if secret_exponent and not generator:
            raise ValueError("generator not specified when secret exponent specified")
        if prefer_uncompressed is None and is_compressed is not None:
            prefer_uncompressed = not is_compressed
        self._prefer_uncompressed = prefer_uncompressed
        self._secret_exponent = secret_exponent
        self._generator = generator
        self._public_pair = public_pair
        self._hash160_uncompressed = None
        self._hash160_compressed = None
        self._hash160 = None
        if hash160:
            if prefer_uncompressed or is_compressed:
                raise ValueError("can't set compression arguments with hash160 input")
            self._hash160 = hash160

        if self._public_pair is None and self._secret_exponent is not None:
            if self._secret_exponent < 1 \
                    or self._secret_exponent >= self._generator.order():
                raise InvalidSecretExponentError()
            public_pair = self._secret_exponent * self._generator
            self._public_pair = public_pair

        if self._public_pair is not None:
            if (None in self._public_pair) or \
               (self._generator and not self._generator.contains_point(*self._public_pair)):
                raise InvalidPublicPairError()

    @classmethod
    def from_sec(class_, sec, generator):
        """
        Create a key from an sec bytestream (which is an encoding of a public pair).
        """
        public_pair = sec_to_public_pair(sec, generator)
        return class_(public_pair=public_pair, is_compressed=is_sec_compressed(sec))

    def is_private(self):
        return self.secret_exponent() is not None

    def secret_exponent(self):
        """
        Return an integer representing the secret exponent (or None).
        """
        return self._secret_exponent

    def wif(self, use_uncompressed=None, ui_context=None):
        """
        Return the WIF representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        secret_exponent = self.secret_exponent()
        if secret_exponent is None:
            return None
        blob = to_bytes_32(secret_exponent)
        if not self._use_uncompressed(use_uncompressed):
            blob += b'\01'
        return self._ui_context(ui_context).wif_for_blob(blob)

    def public_pair(self):
        """
        Return a pair of integers representing the public key (or None).
        """
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

    def sec_as_hex(self, use_uncompressed=None, ui_context=None):
        """
        Return the SEC representation of this key as hex text.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        sec = self.sec(use_uncompressed=use_uncompressed)
        if sec is None:
            return None
        return self._ui_context(ui_context).sec_text_for_blob(sec)

    def hash160(self, use_uncompressed=None):
        """
        Return the hash160 representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        use_uncompressed = self._use_uncompressed(use_uncompressed)
        if self.public_pair() is None:
            if use_uncompressed is not None:
                return None
            return self._hash160

        if use_uncompressed:
            if self._hash160_uncompressed is None:
                self._hash160_uncompressed = hash160(self.sec(use_uncompressed=use_uncompressed))
            return self._hash160_uncompressed

        if self._hash160_compressed is None:
            self._hash160_compressed = hash160(self.sec(use_uncompressed=use_uncompressed))
        return self._hash160_compressed

    def address(self, use_uncompressed=None, ui_context=None):
        """
        Return the public address representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        hash160 = self.hash160(use_uncompressed=use_uncompressed)
        if hash160:
            return self._ui_context(ui_context).address_for_p2pkh(hash160)
        return None

    bitcoin_address = address

    def as_text(self, ui_context=None):
        """
        Return a textual representation of this key.
        """
        if self.secret_exponent():
            return self.wif(ui_context=ui_context)
        sec_hex = self.sec_as_hex(ui_context=ui_context)
        if sec_hex:
            return sec_hex
        return self.address(ui_context=ui_context)

    def public_copy(self):
        if self.secret_exponent() is None:
            return self

        return self.__class__(public_pair=self.public_pair(), prefer_uncompressed=self._prefer_uncompressed,
                              is_compressed=(self._hash160_compressed is not None))

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
        r, s = self._generator.sign(self.secret_exponent(), val)
        return sigencode_der(r, s)

    def verify(self, h, sig, generator=None):
        """
        Return whether a signature is valid for hash h using this key.
        """
        generator = generator or self._generator
        if not generator:
            raise ValueError("generator must be specified")
        val = from_bytes_32(h)
        pubkey = self.public_pair()
        rs = sigdecode_der(sig)
        if self.public_pair() is None:
            # find the pubkey from the signature and see if it matches
            # our key
            possible_pubkeys = generator.possible_public_pairs_for_signature(val, rs)
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
        return generator.verify(pubkey, val, rs)

    def _ui_context(self, ui_context):
        if ui_context is None:
            ui_context = getattr(self, "_default_ui_context", None)
        if ui_context is None:
            raise ValueError("ui_context not set")
        return ui_context

    def _use_uncompressed(self, use_uncompressed=None):
        if use_uncompressed:
            return use_uncompressed
        if use_uncompressed is None:
            return self._prefer_uncompressed
        return False

    def __repr__(self):
        r = self.public_copy()
        if getattr(r, "_default_ui_context", None):
            s = r.as_text()
        elif r.sec():
            s = b2h(r.sec())
        else:
            s = b2h(r.hash160())
        if self.is_private():
            return "private_for <%s>" % s
        return "<%s>" % s
