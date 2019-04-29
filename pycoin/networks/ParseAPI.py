from .parseable_str import parse_b58_double_sha256, parse_bech32, parse_colon_prefix, parseable_str

from pycoin.contrib import segwit_addr
from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.intbytes import int2byte
from pycoin.encoding.hexbytes import b2h, h2b

from .Contract import Contract


class ParseAPI(object):
    def __init__(
            self, network, bip32_prv_prefix=None, bip32_pub_prefix=None, address_prefix=None,
            pay_to_script_prefix=None, bech32_hrp=None, wif_prefix=None, sec_prefix=None):
        self._network = network
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp
        self._wif_prefix = wif_prefix
        self._sec_prefix = sec_prefix

    def parse_b58_hashed(self, s):
        """
        Override me to change how the b58 hashing check is done.
        """
        return parse_b58_double_sha256(s)

    # hierarchical key
    def bip32_seed(self, s):
        """
        Parse a bip32 private key from a seed.
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] not in "HP":
            return None
        if pair[0] == "H":
            try:
                master_secret = h2b(pair[1])
            except ValueError:
                return None
        else:
            master_secret = pair[1].encode("utf8")
        return self._network.keys.bip32_seed(master_secret)

    def bip32_prv(self, s):
        """
        Parse a bip32 private key from a text string ("xprv" type).
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        data = self.parse_b58_hashed(s)
        if data is None or not data.startswith(self._bip32_prv_prefix):
            return None
        return self._network.keys.bip32_deserialize(data)

    def bip32_pub(self, s):
        """
        Parse a bip32 public key from a text string ("xpub" type).
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        data = self.parse_b58_hashed(s)
        if data is None or not data.startswith(self._bip32_pub_prefix):
            return None
        return self._network.keys.bip32_deserialize(data)

    def bip32(self, s):
        """
        Parse a bip32 public key from a text string, either a seed, a prv or a pub.
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        s = parseable_str(s)
        return self.bip32_prv(s) or self.bip32_pub(s)

    def _electrum_to_blob(self, s):
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] != "E":
            return None
        try:
            return h2b(pair[1])
        except ValueError:
            return None

    def electrum_seed(self, s):
        """
        Parse an electrum key from a text string in seed form ("E:xxx" where xxx
        is a 32-character hex string).
        Return a :class:`ElectrumWallet <pycoin.key.electrum.ElectrumWallet>` or None.
        """
        blob = self._electrum_to_blob(s)
        if blob and len(blob) == 16:
            blob = b2h(blob)
            return self._network.keys.electrum_seed(seed=blob)

    def electrum_prv(self, s):
        """
        Parse an electrum private key from a text string in seed form ("E:xxx" where xxx
        is a 64-character hex string).
        Return a :class:`ElectrumWallet <pycoin.key.electrum.ElectrumWallet>` or None.
        """
        blob = self._electrum_to_blob(s)
        if blob and len(blob) == 32:
            mpk = from_bytes_32(blob)
            return self._network.keys.electrum_private(master_private_key=mpk)

    def electrum_pub(self, s):
        """
        Parse an electrum public key from a text string in seed form ("E:xxx" where xxx
        is a 128-character hex string).
        Return a :class:`ElectrumWallet <pycoin.key.electrum.ElectrumWallet>` or None.
        """
        blob = self._electrum_to_blob(s)
        if blob and len(blob) == 64:
            return self._network.keys.electrum_public(master_public_key=blob)

    # address
    def p2pkh(self, s):
        """
        Parse a pay-to-public-key-hash address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        data = self.parse_b58_hashed(s)
        if data is None or not data.startswith(self._address_prefix):
            return None
        size = len(self._address_prefix)
        script = self._network.contract.for_p2pkh(data[size:])
        script_info = self._network.contract.info_for_script(script)
        return Contract(script_info, self._network)

    def p2sh(self, s):
        """
        Parse a pay-to-script-hash address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        data = self.parse_b58_hashed(s)
        if (None in (data, self._pay_to_script_prefix) or
                not data.startswith(self._pay_to_script_prefix)):
            return None
        size = len(self._pay_to_script_prefix)
        script = self._network.contract.for_p2sh(data[size:])
        script_info = self._network.contract.info_for_script(script)
        return Contract(script_info, self._network)

    def _segwit(self, s, blob_len, segwit_attr):
        script_f = getattr(self._network.contract, segwit_attr, None)
        if script_f is None:
            return None
        pair = parse_bech32(s)
        if pair is None or pair[0] != self._bech32_hrp or pair[1] is None:
            return None
        data = pair[1]
        version_byte = int2byte(data[0])
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        if version_byte != b'\0' or len(decoded_data) != blob_len:
            return None
        script = script_f(decoded_data)
        script_info = self._network.contract.info_for_script(script)
        return Contract(script_info, self._network)

    def p2pkh_segwit(self, s):
        """
        Parse a pay-to-pubkey-hash segwit address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        return self._segwit(s, 20, "for_p2pkh_wit")

    def p2sh_segwit(self, s):
        """
        Parse a pay-to-script-hash segwit address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        return self._segwit(s, 32, "for_p2sh_wit")

    # payable (+ all address types)
    def script(self, s):
        """
        Parse a script by compiling it.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        try:
            script = self._network.script.compile(s)
            script_info = self._network.contract.info_for_script(script)
            return Contract(script_info, self._network)
        except Exception:
            return None

    def as_number(self, s):
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return int(s, 16)
        except ValueError:
            pass

    # private key
    def wif(self, s):
        """
        Parse a WIF.
        Return a :class:`Key <pycoin.key.Key>` or None.
        """
        data = self.parse_b58_hashed(s)
        if data is None or not data.startswith(self._wif_prefix):
            return None
        data = data[len(self._wif_prefix):]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return self._network.keys.private(se, is_compressed=is_compressed)

    def secret_exponent(self, s):
        """
        Parse an integer secret exponent.
        Return a :class:`Key <pycoin.key.Key>` or None.
        """
        v = self.as_number(s)
        if v:
            try:
                return self._network.keys.private(v)
            except ValueError:
                pass

    # public key
    def public_pair(self, s):
        """
        Parse a public pair X/Y or X,Y where X is a coordinate and Y is a coordinate or
        the string "even" or "odd".
        Return a :class:`Key <pycoin.key.Key>` or None.
        """
        point = None
        Key = self._network.keys.private
        # BRAIN DAMAGE
        generator = Key(1)._generator
        for c in ",/":
            if c in s:
                s0, s1 = s.split(c, 1)
                v0 = self.as_number(s0)
                if v0:
                    if s1 in ("even", "odd"):
                        is_y_odd = (s1 == "odd")
                        point = generator.points_for_x(v0)[is_y_odd]
                    v1 = self.as_number(s1)
                    if v1:
                        if generator.contains_point(v0, v1):
                            point = generator.Point(v0, v1)
        if point:
            return self._network.keys.public(point)

    def sec(self, s):
        """
        Parse a public pair as a text SEC.
        Return a :class:`Key <pycoin.key.Key>` or None.
        """
        pair = parse_colon_prefix(s)
        if pair is not None and pair[0] == self._wif_prefix:
            s = pair[1]
        try:
            sec = h2b(s)
            return self._network.keys.public(sec)
        except Exception:
            pass

    def address(self, s):
        """
        Parse an address, any of p2pkh, p2sh, p2pkh_segwit, or p2sh_segwit.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>`, or None.
        """
        s = parseable_str(s)
        return self.p2pkh(s) or self.p2sh(s) or self.p2pkh_segwit(s) or self.p2sh_segwit(s)

    def payable(self, s):
        """
        Parse text as either an address or a script to be compiled.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>`, or None.
        """
        s = parseable_str(s)
        return self.address(s) or self.script(s)

    # semantic items
    def hierarchical_key(self, s):
        """
        Parse text as some kind of hierarchical key.
        Return a subclass of :class:`Key <pycoin.key.Key>`, or None.
        """
        s = parseable_str(s)
        for f in [self.bip32_seed, self.bip32_prv, self.bip32_pub,
                  self.electrum_seed, self.electrum_prv, self.electrum_pub]:
            v = f(s)
            if v:
                return v

    def private_key(self, s):
        """
        Parse text as some kind of private key.
        Return a subclass of :class:`Key <pycoin.key.Key>`, or None.
        """
        s = parseable_str(s)
        for f in [self.wif, self.secret_exponent]:
            v = f(s)
            if v:
                return v

    def secret(self, s):
        """
        Parse text either a private key or a private hierarchical key.
        Return a subclass of :class:`Key <pycoin.key.Key>`, or None.
        """
        s = parseable_str(s)
        for f in [self.private_key, self.hierarchical_key]:
            v = f(s)
            if v:
                return v

    def public_key(self, s):
        """
        Parse text as either a public pair or an sec.
        Return a subclass of :class:`Key <pycoin.key.Key>`, or None.
        """
        s = parseable_str(s)
        for f in [self.public_pair, self.sec]:
            v = f(s)
            if v:
                return v

    def input(self, s):
        """
        NOT YET SUPPORTED
        """
        # BRAIN DAMAGE: TODO
        return None

    def tx(self, s):
        """
        NOT YET SUPPORTED
        """
        # BRAIN DAMAGE: TODO
        return None

    def spendable(self, s):
        """
        NOT YET SUPPORTED
        """
        # BRAIN DAMAGE: TODO
        return None

    def script_preimage(self, s):
        """
        NOT YET SUPPORTED
        """
        # BRAIN DAMAGE: TODO
        return None

    def __call__(self, s):
        s = parseable_str(s)
        return (self.payable(s) or
                self.input(s) or
                self.secret(s) or
                self.tx(s))
