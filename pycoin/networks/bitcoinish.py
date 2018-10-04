from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.contrib.who_signed import WhoSigned
from pycoin.ecdsa.secp256k1 import secp256k1_generator
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


def make_output_for_h160(network):
    def f(hash160):
        yield ("hash160", b2h(hash160), None)

        address = network.ui.address_for_p2pkh(hash160)
        yield ("address", address, "%s address" % network.network_name)
        yield ("%s_address" % network.symbol, address, "legacy")
    return f


def make_parse(network):

    def parse(s):
        pass

    from pycoin.ui.Parser import parse_b58, parse_colon_prefix
    from pycoin.encoding.bytes32 import from_bytes_32

    def parse_wif(s):
        data = parse_b58(s)
        if data is None or data[:1] != network.ui._wif_prefix:
            return None
        data = data[1:]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return network.extras.Key(se)

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
        if len(blob) == 16:
            blob = b2h(blob)
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, initial_key=blob)

    def parse_electrum_prv(s):
        blob = parse_electrum_to_blob(s)
        if len(blob) == 32:
            mpk = from_bytes_32(blob)
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, master_private_key=mpk)

    def parse_electrum_pub(s):
        blob = parse_electrum_to_blob(s)
        if len(blob) == 64:
            return network.ui._electrum_class(
                generator=network.ui._key_class._default_generator, master_public_key=blob)

    parse.wif = parse_wif
    parse.bip32_prv = parse_bip32_prv
    parse.bip32_pub = parse_bip32_pub
    parse.bip32_seed = parse_bip32_seed
    parse.electrum_seed = parse_electrum_seed
    parse.electrum_prv = parse_electrum_prv
    parse.electrum_pub = parse_electrum_pub


    """
    def parse_p2pkh(s):
        data = parse_b58(s)
        if data is None or not data.startswith(network.ui._address_prefix):
            return None
        # BRAIN DAMAGE: figure out Payable
        return Payable()

    TODO:
    parse.p2pkh = parse_p2pkh
    parse.p2sh
    parse.p2pkh_segwit
    parse.p2sh_segwit
    parse.secret_exponent = parse_secret_exponent
    parse.address = parse_address
    parse.script = parse_script
    parse.sec = parse_sec
    parse.spendable = parse_spendable
    parse.script_preimage = parse_script_preimage
    """

    # semantic items
    #tx
    #keychain_secret
    #input
    #payable (address + script)
    #address

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
    network_kwargs = {k: kwargs.get(k) for k in NETWORK_KEYS if k in kwargs}
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
    network.output_for_h160 = make_output_for_h160(network)
    network.BIP32Node = network.extras.BIP32Node
    network.Key = network.extras.Key
    network.ElectrumKey = network.extras.ElectrumKey
    network.Keychain = Keychain
    network.parse = make_parse(network)
    return network
