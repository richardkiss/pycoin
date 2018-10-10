from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.contrib.who_signed import WhoSigned
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding.sec import is_sec_compressed, sec_to_public_pair
from pycoin.key.Keychain import Keychain
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages,
    standard_message_post_unpacks, standard_streamer, standard_parsing_functions
)
from pycoin.encoding.hexbytes import b2h, h2b
from pycoin.ui.uiclass import UI
from pycoin.vm.annotate import Annotate
from pycoin.vm.ScriptInfo import ScriptInfo


class Extras(object):
    def __init__(self, script_tools, ui):
        self.annotate = Annotate(script_tools, ui)
        self.Key = ui._key_class
        self.BIP32Node = ui._bip32node_class
        self.ElectrumKey = ui._electrum_class
        who_signed = WhoSigned(script_tools, self.Key._default_generator)
        self.who_signed_tx = who_signed.who_signed_tx
        self.public_pairs_signed = who_signed.public_pairs_signed
        self.extract_secs = who_signed.extract_secs
        self.extract_signatures = who_signed.extract_signatures
        self.public_pairs_for_script = who_signed.public_pairs_for_script


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
            key = network.extras.BIP32Node.deserialize(b'0000' + key_data)
        elif len(key_data) in (32, 64):
            key = network.extras.ElectrumWallet.deserialize(key_data)
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

        ui_context = network.ui
        network_name = network.network_name
        hash160_c = key.hash160(use_uncompressed=False)
        hash160_u = key.hash160(use_uncompressed=True)
        hash160 = None
        if hash160_c is None and hash160_u is None:
            hash160 = key.hash160()

        yield ("hash160", b2h(hash160 or hash160_c), None)

        if hash160_c and hash160_u:
            yield ("hash160_uncompressed", b2h(hash160_u), " uncompressed")

        address = ui_context.address_for_p2pkh(hash160 or hash160_c)
        yield ("address", address, "%s address" % network_name)
        yield ("%s_address" % network.symbol, address, "legacy")

        if hash160_c and hash160_u:
            address = key.address(use_uncompressed=True)
            yield ("address_uncompressed", address, "%s address uncompressed" % network_name)
            yield ("%s_address_uncompressed" % network.symbol, address, "legacy")

        # don't print segwit addresses unless we're sure we have a compressed key
        if hash160_c and hasattr(network, "ui") and getattr(network.ui, "_bech32_hrp"):
            address_segwit = network.ui.address_for_p2pkh_wit(hash160_c)
            if address_segwit:
                # this network seems to support segwit
                yield ("address_segwit", address_segwit, "%s segwit address" % network_name)
                yield ("%s_address_segwit" % network.symbol, address_segwit, "legacy")

                p2sh_script = network.script_info.script_for_p2pkh_wit(hash160_c)
                p2s_address = network.ui.address_for_p2s(p2sh_script)
                if p2s_address:
                    yield ("p2sh_segwit", p2s_address, None)

                p2sh_script_hex = b2h(p2sh_script)
                yield ("p2sh_segwit_script", p2sh_script_hex, " corresponding p2sh script")

    return f


class BitcoinishPayable(object):
    def __init__(self, script_info, network):
        self._script_info = script_info
        self._network = network

    def address(self):
        return self._network.ui.address_for_script_info(self._script_info)

    def script(self):
        return self._network.script_info.script_for_info(self._script_info)

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


def make_parse(network):

    from pycoin.contrib import segwit_addr
    from pycoin.encoding.bytes32 import from_bytes_32
    from pycoin.intbytes import int2byte
    from pycoin.ui.Parser import parse_b58, parse_bech32, parse_colon_prefix, parseable_str

    def parse_wif(s):
        data = parse_b58(s)
        if data is None or data[:1] != network.ui._wif_prefix:
            return None
        data = data[1:]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return network.extras.Key(se, is_compressed=is_compressed)

    def parse_bip32_prv(s):
        data = parse_b58(s)
        if data is None or not data.startswith(network.ui._bip32_prv_prefix):
            return None
        return network.extras.BIP32Node.deserialize(data)

    def parse_bip32_pub(s):
        data = parse_b58(s)
        if data is None or not data.startswith(network.ui._bip32_pub_prefix):
            return None
        return network.extras.BIP32Node.deserialize(data)

    def parse_bip32_seed(s):
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
        return network.extras.BIP32Node.from_master_secret(master_secret)

    def parse_electrum_to_blob(s):
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] != "E":
            return None
        try:
            return h2b(pair[1])
        except ValueError:
            return None

    def parse_electrum_seed(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 16:
            blob = b2h(blob)
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, initial_key=blob)

    def parse_electrum_prv(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 32:
            mpk = from_bytes_32(blob)
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, master_private_key=mpk)

    def parse_electrum_pub(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 64:
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, master_public_key=blob)

    def parse_p2pkh(s):
        data = parse_b58(s)
        if data is None or not data.startswith(network.ui._address_prefix):
            return None
        script = network.script_info.script_for_p2pkh(data[1:])
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_p2sh(s):
        data = parse_b58(s)
        if (None in (data, network.ui._pay_to_script_prefix) or
                not data.startswith(network.ui._pay_to_script_prefix)):
            return None
        script = network.script_info.script_for_p2sh(data[1:])
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_segwit(s, blob_len, script_f):
        pair = parse_bech32(s)
        if pair is None or pair[0] != network.ui._bech32_hrp or pair[1] is None:
            return None
        data = pair[1]
        version_byte = int2byte(data[0])
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        if version_byte != b'\0' or len(decoded_data) != blob_len:
            return None
        script = script_f(decoded_data)
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_p2pkh_segwit(s):
        return parse_segwit(s, 20, network.script_info.script_for_p2pkh_wit)

    def parse_p2sh_segwit(s):
        return parse_segwit(s, 32, network.script_info.script_for_p2sh_wit)

    def parse_script(s):
        try:
            script = network.script_tools.compile(s)
            script_info = network.script_info.info_for_script(script)
            return BitcoinishPayable(script_info, network)
        except Exception:
            return None

    def parse_as_number(s):
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return int(s, 16)
        except ValueError:
            pass

    def parse_secret_exponent(s):
        v = parse_as_number(s)
        Key = network.extras.Key
        if v and 0 < v < Key._default_generator.order():
            return Key(secret_exponent=v)

    def parse_public_pair(s):
        point = None
        Key = network.extras.Key
        generator = Key._default_generator
        for c in ",/":
            if c in s:
                s0, s1 = s.split(c, 1)
                v0 = parse_as_number(s0)
                if v0:
                    if s1 in ("even", "odd"):
                        is_y_odd = (s1 == "odd")
                        point = generator.points_for_x(v0)[is_y_odd]
                    v1 = parse_as_number(s1)
                    if v1:
                        if generator.contains_point(v0, v1):
                            point = generator.Point(v0, v1)
        if point:
            return Key(public_pair=point)

    def parse_sec(s):
        pair = parse_colon_prefix(s)
        if pair is not None and pair[0] == network.ui._wif_prefix:
            s = pair[1]
        try:
            sec = h2b(s)
            public_pair = sec_to_public_pair(sec, network.extras.Key._default_generator)
            is_compressed = is_sec_compressed(sec)
            return network.extras.Key(public_pair=public_pair, is_compressed=is_compressed)
        except Exception:
            pass

    def parse_address(s):
        s = parseable_str(s)
        return parse_p2pkh(s) or parse_p2sh(s) or parse_p2pkh_segwit(s) or parse_p2sh_segwit(s)

    def parse_payable(s):
        s = parseable_str(s)
        return parse_address(s) or parse_script(s)

    def parse_hierarchical_key(s):
        s = parseable_str(s)
        for f in [parse_bip32_seed, parse_bip32_prv, parse_bip32_pub,
                  parse_electrum_seed, parse_electrum_prv, parse_electrum_pub]:
            v = f(s)
            if v:
                return v

    def parse_private_key(s):
        s = parseable_str(s)
        for f in [parse_wif, parse_secret_exponent]:
            v = f(s)
            if v:
                return v

    def parse_public_key(s):
        s = parseable_str(s)
        for f in [parse_public_pair, parse_sec]:
            v = f(s)
            if v:
                return v

    def parse(s):
        s = parseable_str(s)
        return (parse_payable(s) or
                parse_input(s) or
                parse_keychain_secret(s) or
                parse_tx(s))

    # hierarchical key
    parse.bip32_seed = parse_bip32_seed
    parse.bip32_prv = parse_bip32_prv
    parse.bip32_pub = parse_bip32_pub
    parse.electrum_seed = parse_electrum_seed
    parse.electrum_prv = parse_electrum_prv
    parse.electrum_pub = parse_electrum_pub

    # private key
    parse.wif = parse_wif
    parse.secret_exponent = parse_secret_exponent

    # public key
    parse.public_pair = parse_public_pair
    parse.sec = parse_sec

    # address
    parse.p2pkh = parse_p2pkh
    parse.p2sh = parse_p2sh
    parse.p2pkh_segwit = parse_p2pkh_segwit
    parse.p2sh_segwit = parse_p2sh_segwit

    # payable (+ all address types)
    parse.script = parse_script

    #parse.spendable = parse_spendable
    #parse.script_preimage = parse_script_preimage

    # semantic items
    parse.hierarchical_key = parse_hierarchical_key
    parse.private_key = parse_private_key
    parse.public_key = parse_public_key
    parse.address = parse_address
    parse.payable = parse_payable
    #parse.input = parse_input
    #parse.keychain_secret = parse_keychain_secret
    #parse.tx = parse_tx

    return parse


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
    network.script_info = ScriptInfo(network.script_tools)

    UI_KEYS = ("bip32_prv_prefix bip32_pub_prefix wif_prefix sec_prefix "
               "address_prefix pay_to_script_prefix bech32_hrp").split()
    ui_kwargs = {k: kwargs[k] for k in UI_KEYS if k in kwargs}

    network.ui = UI(network.script_info, generator, **ui_kwargs)
    network.extras = Extras(network.script_tools, network.ui)

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
    network.output_for_secret_exponent = make_output_for_secret_exponent(network.extras.Key)
    network.output_for_public_pair = make_output_for_public_pair(network.extras.Key, network)
    network.BIP32Node = network.extras.BIP32Node
    network.Key = network.extras.Key
    network.ElectrumKey = network.extras.ElectrumKey
    network.Keychain = Keychain
    network.parse = make_parse(network)
    return network
