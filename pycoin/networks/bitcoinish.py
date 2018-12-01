from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.contrib.who_signed import WhoSigned
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.key.Keychain import Keychain
from pycoin.key.Key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.electrum import ElectrumWallet
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages,
    standard_message_post_unpacks, standard_streamer, standard_parsing_functions
)
from pycoin.encoding.hexbytes import b2h, h2b
from pycoin.ui.uiclass import UI
from pycoin.vm.annotate import Annotate
from pycoin.vm.CanonicalScript import CanonicalScript

from .AddressAPI import AddressAPI
from .ParseAPI import ParseAPI
from .ScriptAPI import ScriptAPI


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

    ui_class = kwargs.get("ui_class", UI)
    ui = ui_class(generator, **ui_kwargs)

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

    parse_api_class = kwargs.get("parse_api_class", ParseAPI)
    network.parse = parse_api_class(network, ui)

    network.address = AddressAPI(canonical_scripts, ui)

    network.script = ScriptAPI(network, canonical_scripts, ui)

    network.script_info_for_script = canonical_scripts.info_for_script

    network.bip32_as_string = ui.bip32_as_string
    network.sec_text_for_blob = ui.sec_text_for_blob
    network.wif_for_blob = ui.wif_for_blob

    network.annotate = Annotate(network.script_tools, network.address)

    network.who_signed = WhoSigned(
        network.script_tools, network.address, network.Key._default_generator)

    return network
