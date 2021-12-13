from .parseable_str import parse_b58_double_sha256, parse_bech32, parse_colon_prefix, parseable_str

from pycoin.contrib import bech32m
from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.intbytes import int2byte
from pycoin.encoding.hexbytes import b2h, h2b

from .Contract import Contract


def hparse(api, pub_prv, key_type, s):
    """
    Generalize parsing bip32-type b58-encoded strings.
    """
    data = api.parse_b58_hashed(s)
    attr_name = "_%s_%s_prefix" % (key_type, pub_prv)
    prefix = getattr(api, attr_name, None)
    if data is None or prefix is None or not data.startswith(prefix):
        return None
    parse_method_name = "%s_deserialize" % key_type
    parse_method = getattr(api._network.keys, parse_method_name, lambda *args: None)
    return parse_method(data)


class ParseAPI(object):
    def __init__(
            self, network, bip32_prv_prefix=None, bip32_pub_prefix=None, bip49_prv_prefix=None,
            bip49_pub_prefix=None, bip84_prv_prefix=None, bip84_pub_prefix=None, address_prefix=None,
            pay_to_script_prefix=None, bech32_hrp=None, wif_prefix=None, sec_prefix=None):
        self._network = network
        self._bip32_prv_prefix = bip32_prv_prefix
        self._bip32_pub_prefix = bip32_pub_prefix
        self._bip49_prv_prefix = bip49_prv_prefix
        self._bip49_pub_prefix = bip49_pub_prefix
        self._bip84_prv_prefix = bip84_prv_prefix
        self._bip84_pub_prefix = bip84_pub_prefix
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

    # hierarchical key
    def hd_seed(self, s):
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
        return self._network.keys.hd_seed(master_secret)

    def bip32_prv(self, s):
        """
        Parse a bip32 private key from a text string ("xprv" type).
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        return hparse(self, "prv", "bip32", s)

    def bip32_pub(self, s):
        """
        Parse a bip32 public key from a text string ("xpub" type).
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        return hparse(self, "pub", "bip32", s)

    def bip32(self, s):
        """
        Parse a bip32 public key from a text string, either a seed, a prv or a pub.
        Return a :class:`BIP32 <pycoin.key.BIP32Node.BIP32Node>` or None.
        """
        s = parseable_str(s)
        return self.bip32_prv(s) or self.bip32_pub(s)

    def bip49_prv(self, s):
        """
        Parse a bip84 private key from a text string ("yprv" type).
        Return a :class:`BIP49 <pycoin.key.BIP49Node.BIP49Node>` or None.
        """
        return hparse(self, "prv", "bip49", s)

    def bip49_pub(self, s):
        """
        Parse a bip84 public key from a text string ("ypub" type).
        Return a :class:`BIP49 <pycoin.key.BIP49Node.BIP49Node>` or None.
        """
        return hparse(self, "pub", "bip49", s)

    def bip49(self, s):
        """
        Parse a bip49 public key from a text string, either a seed, a prv or a pub.
        Return a :class:`BIP49 <pycoin.key.BIP49Node.BIP49Node>` or None.
        """
        s = parseable_str(s)
        return self.bip49_prv(s) or self.bip49_pub(s)

    def bip84_prv(self, s):
        """
        Parse a bip84 private key from a text string ("zprv" type).
        Return a :class:`BIP84 <pycoin.key.BIP84Node.BIP84Node>` or None.
        """
        return hparse(self, "prv", "bip84", s)

    def bip84_pub(self, s):
        """
        Parse a bip84 public key from a text string ("zpub" type).
        Return a :class:`BIP84 <pycoin.key.BIP84Node.BIP84Node>` or None.
        """
        return hparse(self, "pub", "bip84", s)

    def bip84(self, s):
        """
        Parse a bip84 public key from a text string, either a seed, a prv or a pub.
        Return a :class:`BIP84 <pycoin.key.BIP84Node.BIP84Node>` or None.
        """
        s = parseable_str(s)
        return self.bip84_prv(s) or self.bip84_pub(s)

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

    def _bech32m(self, s, expected_version, blob_len, segwit_attr):
        v = parse_bech32(s)
        if v is None:
            return None
        (hr_prefix, version, decoded_data, spec) = v

        script_f = getattr(self._network.contract, segwit_attr, None)
        if script_f is None:
            return None

        if hr_prefix != self._bech32_hrp:
            return None
        if len(decoded_data) != blob_len:
            return None
        if expected_version != version:
            return None
        if version == 0 and spec != bech32m.Encoding.BECH32:
            return None
        if version != 0 and spec != bech32m.Encoding.BECH32M:
            return None
        script = script_f(decoded_data)
        script_info = self._network.contract.info_for_script(script)
        return Contract(script_info, self._network)

    def p2pkh_segwit(self, s):
        """
        Parse a pay-to-pubkey-hash segwit address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        return self._bech32m(s, 0, 20, "for_p2pkh_wit")

    def p2sh_segwit(self, s):
        """
        Parse a pay-to-script-hash segwit address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        return self._bech32m(s, 0, 32, "for_p2sh_wit")

    def p2tr(self, s):
        """
        Parse a pay-to-taproot segwit address.
        Return a :class:`Contract <pycoin.networks.Contract.Contract>` or None.
        """
        return self._bech32m(s, 1, 32, "for_p2tr")

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
        return (
            self.p2pkh(s) or self.p2sh(s) or self.p2pkh_segwit(s) or self.p2sh_segwit(s)
            or self.p2tr(s)
        )

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
        for f in [self.bip32_seed, self.bip32, self.bip49, self.bip84,
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
