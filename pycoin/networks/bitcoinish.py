from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.contrib.who_signed import WhoSigned
from pycoin.contrib import segwit_addr
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.encoding.sec import is_sec_compressed, sec_to_public_pair
from pycoin.intbytes import int2byte
from pycoin.key.Keychain import Keychain
from pycoin.key.Key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.electrum import ElectrumWallet
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages,
    standard_message_post_unpacks, standard_streamer, standard_parsing_functions
)
from pycoin.encoding.hexbytes import b2h, h2b
from pycoin.ui.parseable_str import parse_b58_double_sha256, parse_bech32, parse_colon_prefix, parseable_str
from pycoin.ui.uiclass import UI
from pycoin.vm.annotate import Annotate
from pycoin.vm.CanonicalScript import CanonicalScript


class Network(object):
    def __init__(self, symbol, network_name, subnet_name):
        self.symbol = symbol
        self.network_name = network_name
        self.subnet_name = subnet_name

    def full_name(self):
        return "%s %s" % (self.network_name, self.subnet_name)

    def __repr__(self):
        return "<Network %s>" % self.full_name()


def make_output_for_hwif(network):
    def f(key_data, network, subkey_path, add_output):

        if len(key_data) == 74:
            key = network.BIP32Node.deserialize(b'0000' + key_data)
        elif len(key_data) in (32, 64):
            key = network.ElectrumWallet.deserialize(key_data)
        else:
            return
        yield ("wallet_key", key.hwif(as_private=key.is_private()), None)
        if key.is_private():
            yield ("public_version", key.hwif(as_private=False), None)

        child_number = key.child_index()
        if child_number >= 0x80000000:
            wc = child_number - 0x80000000
            child_index = "%dH (%d)" % (wc, child_number)
        else:
            child_index = "%d" % child_number
        yield ("tree_depth", "%d" % key.tree_depth(), None)
        yield ("fingerprint", b2h(key.fingerprint()), None)
        yield ("parent_fingerprint", b2h(key.parent_fingerprint()), "parent f'print")
        yield ("child_index", child_index, None)
        yield ("chain_code", b2h(key.chain_code()), None)

        yield ("private_key", "yes" if key.is_private() else "no", None)
    return f


def make_output_for_secret_exponent(Key):
    def f(secret_exponent):
        yield ("secret_exponent", '%d' % secret_exponent, None)
        yield ("secret_exponent_hex", '%x' % secret_exponent, " hex")
        key = Key(secret_exponent)
        yield ("wif", key.wif(use_uncompressed=False), None)
        yield ("wif_uncompressed", key.wif(use_uncompressed=True), " uncompressed")
    return f


def make_output_for_public_pair(Key, network):
    def f(public_pair):
        yield ("public_pair_x", '%d' % public_pair[0], None)
        yield ("public_pair_y", '%d' % public_pair[1], None)
        yield ("public_pair_x_hex", '%x' % public_pair[0], " x as hex")
        yield ("public_pair_y_hex", '%x' % public_pair[1], " y as hex")
        yield ("y_parity", "odd" if (public_pair[1] & 1) else "even", None)

        key = Key(public_pair=public_pair)
        yield ("key_pair_as_sec", b2h(key.sec(use_uncompressed=False)), None)
        yield ("key_pair_as_sec_uncompressed", b2h(key.sec(use_uncompressed=True)), " uncompressed")

        network_name = network.network_name
        hash160_c = key.hash160(use_uncompressed=False)
        hash160_u = key.hash160(use_uncompressed=True)
        hash160 = None
        if hash160_c is None and hash160_u is None:
            hash160 = key.hash160()

        yield ("hash160", b2h(hash160 or hash160_c), None)

        if hash160_c and hash160_u:
            yield ("hash160_uncompressed", b2h(hash160_u), " uncompressed")

        address = network.address.for_p2pkh(hash160 or hash160_c)
        yield ("address", address, "%s address" % network_name)
        yield ("%s_address" % network.symbol, address, "legacy")

        if hash160_c and hash160_u:
            address = key.address(use_uncompressed=True)
            yield ("address_uncompressed", address, "%s address uncompressed" % network_name)
            yield ("%s_address_uncompressed" % network.symbol, address, "legacy")

        # don't print segwit addresses unless we're sure we have a compressed key
        if hash160_c and hasattr(network.address, "for_p2pkh_wit"):
            address_segwit = network.address.for_p2pkh_wit(hash160_c)
            if address_segwit:
                # this network seems to support segwit
                yield ("address_segwit", address_segwit, "%s segwit address" % network_name)
                yield ("%s_address_segwit" % network.symbol, address_segwit, "legacy")

                p2sh_script = network.script.for_p2pkh_wit(hash160_c)
                p2s_address = network.address.for_p2s(p2sh_script)
                if p2s_address:
                    yield ("p2sh_segwit", p2s_address, None)

                p2sh_script_hex = b2h(p2sh_script)
                yield ("p2sh_segwit_script", p2sh_script_hex, " corresponding p2sh script")

    return f


class BitcoinishPayable(object):
    def __init__(self, script_info, network):
        self._script_info = script_info
        self._network = network

    def info(self):
        return self._script_info

    def hash160(self):
        return self._script_info.get("hash160")

    def address(self):
        return self._network.address.for_script_info(self._script_info)

    def script(self):
        return self._network.script.for_info(self._script_info)

    def disassemble(self):
        return self._network.script_tools.disassemble(self.script())

    def output(self):
        hash160 = self._script_info.get("hash160", None)
        if hash160:
            yield ("hash160", b2h(hash160), None)

        address = self.address()
        yield ("address", address, "%s address" % self._network.network_name)
        yield ("%s_address" % self._network.symbol, address, "legacy")

    def __repr__(self):
        return "<%s>" % self.address()


class ParseAPI(object):
    def __init__(self, network, ui):
        self._network = network
        self._ui = ui

    # hierarchical key
    def bip32_seed(self, s):
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
        return self._network.BIP32Node.from_master_secret(master_secret)

    def bip32_prv(self, s):
        data = parse_b58_double_sha256(s)
        if data is None or not data.startswith(self._ui._bip32_prv_prefix):
            return None
        return self._network.BIP32Node.deserialize(data)

    def bip32_pub(self, s):
        data = parse_b58_double_sha256(s)
        if data is None or not data.startswith(self._ui._bip32_pub_prefix):
            return None
        return self._network.BIP32Node.deserialize(data)

    def electrum_to_blob(self, s):
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] != "E":
            return None
        try:
            return h2b(pair[1])
        except ValueError:
            return None

    def electrum_seed(self, s):
        blob = self.electrum_to_blob(s)
        if blob and len(blob) == 16:
            blob = b2h(blob)
            return self._network.ElectrumKey(
                generator=self._network.Key._default_generator, initial_key=blob)

    def electrum_prv(self, s):
        blob = self.electrum_to_blob(s)
        if blob and len(blob) == 32:
            mpk = from_bytes_32(blob)
            return self._network.ElectrumKey(
                generator=self._network.Key._default_generator, master_private_key=mpk)

    def electrum_pub(self, s):
        blob = self.electrum_to_blob(s)
        if blob and len(blob) == 64:
            return self._network.ElectrumKey(
                generator=self._network.Key._default_generator, master_public_key=blob)

    # address
    def p2pkh(self, s):
        data = parse_b58_double_sha256(s)
        if data is None or not data.startswith(self._ui._address_prefix):
            return None
        size = len(self._ui._address_prefix)
        script = self._network.script.for_p2pkh(data[size:])
        script_info = self._network.script_info_for_script(script)
        return BitcoinishPayable(script_info, self._network)

    def p2sh(self, s):
        data = parse_b58_double_sha256(s)
        if (None in (data, self._ui._pay_to_script_prefix) or
                not data.startswith(self._ui._pay_to_script_prefix)):
            return None
        size = len(self._ui._pay_to_script_prefix)
        script = self._network.script.for_p2sh(data[size:])
        script_info = self._network.script_info_for_script(script)
        return BitcoinishPayable(script_info, self._network)

    def segwit(self, s, blob_len, segwit_attr):
        script_f = getattr(self._network.script, segwit_attr, None)
        if script_f is None:
            return None
        pair = parse_bech32(s)
        if pair is None or pair[0] != self._ui._bech32_hrp or pair[1] is None:
            return None
        data = pair[1]
        version_byte = int2byte(data[0])
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        if version_byte != b'\0' or len(decoded_data) != blob_len:
            return None
        script = script_f(decoded_data)
        script_info = self._network.script_info_for_script(script)
        return BitcoinishPayable(script_info, self._network)

    def p2pkh_segwit(self, s):
        return self.segwit(s, 20, "for_p2pkh_wit")

    def p2sh_segwit(self, s):
        return self.segwit(s, 32, "for_p2sh_wit")

    # payable (+ all address types)
    def script(self, s):
        try:
            script = self._network.script_tools.compile(s)
            script_info = self._network.script_info_for_script(script)
            return BitcoinishPayable(script_info, self._network)
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
        data = parse_b58_double_sha256(s)
        if data is None or not data.startswith(self._ui._wif_prefix):
            return None
        data = data[len(self._ui._wif_prefix):]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return self._network.Key(se, is_compressed=is_compressed)

    def secret_exponent(self, s):
        v = self.as_number(s)
        Key = self._network.Key
        if v and 0 < v < Key._default_generator.order():
            return Key(secret_exponent=v)

    # public key
    def public_pair(self, s):
        point = None
        Key = self._network.Key
        generator = Key._default_generator
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
            return Key(public_pair=point)

    def sec(self, s):
        pair = parse_colon_prefix(s)
        if pair is not None and pair[0] == self._ui._wif_prefix:
            s = pair[1]
        try:
            sec = h2b(s)
            public_pair = sec_to_public_pair(sec, self._network.Key._default_generator)
            is_compressed = is_sec_compressed(sec)
            return self._network.Key(public_pair=public_pair, is_compressed=is_compressed)
        except Exception:
            pass

    def address(self, s):
        s = parseable_str(s)
        return self.p2pkh(s) or self.p2sh(s) or self.p2pkh_segwit(s) or self.p2sh_segwit(s)

    def payable(self, s):
        s = parseable_str(s)
        return self.address(s) or self.script(s)

    # semantic items
    def hierarchical_key(self, s):
        s = parseable_str(s)
        for f in [self.bip32_seed, self.bip32_prv, self.bip32_pub,
                  self.electrum_seed, self.electrum_prv, self.electrum_pub]:
            v = f(s)
            if v:
                return v

    def private_key(self, s):
        s = parseable_str(s)
        for f in [self.wif, self.secret_exponent]:
            v = f(s)
            if v:
                return v

    def secret(self, s):
        s = parseable_str(s)
        for f in [self.private_key, self.hierarchical_key]:
            v = f(s)
            if v:
                return v

    def public_key(self, s):
        s = parseable_str(s)
        for f in [self.public_pair, self.sec]:
            v = f(s)
            if v:
                return v

    def input(self, s):
        # BRAIN DAMAGE: TODO
        return None

    def tx(self, s):
        # BRAIN DAMAGE: TODO
        return None

    def spendable(self, s):
        # BRAIN DAMAGE: TODO
        return None

    def script_preimage(self, s):
        # BRAIN DAMAGE: TODO
        return None

    def __call__(self, s):
        s = parseable_str(s)
        return (self.payable(s) or
                self.input(s) or
                self.secret(s) or
                self.tx(s))


class AddressAPI(object):

    def __init__(self, ui, canonical_scripts):
        self._ui = ui
        self._canonical_scripts = canonical_scripts

    def address_for_script(self, script):
        info = self._canonical_scripts.info_for_script(script)
        return self._ui.address_for_script_info(info)

    def for_script_info(self, s):
        return self._ui.address_for_script_info(s)

    def for_script(self, s):
        return self.address_for_script(s)

    def for_p2s(self, s):
        return self._ui.address_for_p2s(s)

    def for_p2sh(self, s):
        return self._ui.address_for_p2sh(s)

    def for_p2pkh(self, s):
        return self._ui.address_for_p2pkh(s)

    def for_p2s_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2s_wit(s)

    def for_p2sh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2sh_wit(s)

    def for_p2pkh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._ui.address_for_p2pkh_wit(s)


class ScriptAPI(object):
    def __init__(self, network, canonical_scripts, ui):
        self._network = network
        self._canonical_scripts = canonical_scripts
        self._ui = ui

    def for_address(self, address):
        info = self._network.parse.address(address)
        if info:
            return info.script()

    def for_multisig(self, m, sec_keys):
        return self._canonical_scripts.script_for_multisig(m, sec_keys)

    def for_nulldata(self, s):
        return self._canonical_scripts.script_for_nulldata(s)

    def for_nulldata_push(self, s):
        return self._canonical_scripts.script_for_nulldata_push(s)

    def for_p2pk(self, s):
        return self._canonical_scripts.script_for_p2pk(s)

    def for_p2pkh(self, s):
        return self._canonical_scripts.script_for_p2pkh(s)

    def for_p2sh(self, s):
        return self._canonical_scripts.script_for_p2sh(s)

    def for_p2s(self, s):
        return self._canonical_scripts.script_for_p2s(s)

    def for_p2pkh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._canonical_scripts.script_for_p2pkh_wit(s)

    def for_p2s_wit(self, s):
        if self._ui._bech32_hrp:
            return self._canonical_scripts.script_for_p2s_wit(s)

    def for_p2sh_wit(self, s):
        if self._ui._bech32_hrp:
            return self._canonical_scripts.script_for_p2sh_wit(s)

    def for_info(self, s):
        return self._canonical_scripts.script_for_info(s)


def create_bitcoinish_network(symbol, network_name, subnet_name, **kwargs):
    # potential kwargs:
    #   tx, block, magic_header_hex, default_port, dns_bootstrap,
    #   wif_prefix_hex, address_prefix_hex, pay_to_script_prefix_hex
    #   bip32_prv_prefix_hex, bip32_pub_prefix_hex, sec_prefix, scriptTools

    network = Network(symbol, network_name, subnet_name)

    generator = kwargs.get("generator", secp256k1_generator)
    kwargs.setdefault("sec_prefix", "%sSEC" % symbol.upper())
    KEYS_TO_H2B = ("bip32_prv_prefix bip32_pub_prefix wif_prefix address_prefix "
                   "pay_to_script_prefix sec_prefix magic_header").split()
    for k in KEYS_TO_H2B:
        k_hex = "%s_hex" % k
        if k_hex in kwargs:
            kwargs[k] = h2b(kwargs[k_hex])

    network.script_tools = kwargs.get("scriptTools", BitcoinScriptTools)
    canonical_scripts = CanonicalScript(network.script_tools)

    UI_KEYS = ("bip32_prv_prefix bip32_pub_prefix wif_prefix sec_prefix "
               "address_prefix pay_to_script_prefix bech32_hrp").split()
    ui_kwargs = {k: kwargs[k] for k in UI_KEYS if k in kwargs}

    ui = UI(generator, **ui_kwargs)

    network.Key = Key.make_subclass(network=network, generator=generator)
    network.ElectrumKey = ElectrumWallet.make_subclass(network=network, generator=generator)
    network.BIP32Node = BIP32Node.make_subclass(network=network, generator=generator)

    NETWORK_KEYS = "network_name subnet_name dns_bootstrap default_port magic_header".split()
    for k in NETWORK_KEYS:
        if k in kwargs:
            setattr(network, k, kwargs[k])

    network.Tx = network.tx = kwargs.get("tx") or Tx
    network.Block = network.block = kwargs.get("block") or Block.make_subclass(network.tx)

    streamer = standard_streamer(standard_parsing_functions(network.block, network.tx))
    network.parse_message, network.pack_message = make_parser_and_packer(
        streamer, standard_messages(), standard_message_post_unpacks(streamer))

    network.output_for_hwif = make_output_for_hwif(network)
    network.output_for_secret_exponent = make_output_for_secret_exponent(network.Key)
    network.output_for_public_pair = make_output_for_public_pair(network.Key, network)
    network.Keychain = Keychain

    network.parse = ParseAPI(network, ui)

    network.address = AddressAPI(ui, canonical_scripts)

    network.script = ScriptAPI(network, canonical_scripts, ui)

    network.script_info_for_script = canonical_scripts.info_for_script

    network.bip32_as_string = ui.bip32_as_string
    network.sec_text_for_blob = ui.sec_text_for_blob
    network.wif_for_blob = ui.wif_for_blob

    network.annotate = Annotate(network.script_tools, network.address)

    network.who_signed = WhoSigned(
        network.script_tools, network.address, network.Key._default_generator)

    return network
