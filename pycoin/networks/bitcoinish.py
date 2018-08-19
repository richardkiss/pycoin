from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.contrib.who_signed import WhoSigned
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages,
    standard_message_post_unpacks, standard_streamer, standard_parsing_functions
)
from pycoin.encoding.hexbytes import h2b
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

    scriptTools = kwargs.get("scriptTools", BitcoinScriptTools)
    _script_info = ScriptInfo(scriptTools)
    UI_KEYS = ("bip32_prv_prefix bip32_pub_prefix wif_prefix sec_prefix "
               "address_prefix pay_to_script_prefix bech32_hrp").split()
    ui_kwargs = {k: kwargs[k] for k in UI_KEYS if k in kwargs}
    ui = UI(_script_info, generator, **ui_kwargs)

    extras = Extras(scriptTools, ui)
    kwargs["ui"] = ui
    kwargs["extras"] = extras
    kwargs.setdefault("tx", Tx)
    kwargs.setdefault("block", Block.make_subclass(kwargs["tx"]))

    NETWORK_KEYS = ("network_name subnet_name tx block ui extras "
                    "dns_bootstrap default_port magic_header").split()
    network_kwargs = {k: kwargs.get(k) for k in NETWORK_KEYS if k in kwargs}
    network_kwargs["code"] = symbol  # BRAIN DAMAGE

    for k, v in network_kwargs.items():
        setattr(network, k, v)

    streamer = standard_streamer(standard_parsing_functions(network.block, network.tx))
    network.parse_message, network.pack_message = make_parser_and_packer(
        streamer, standard_messages(), standard_message_post_unpacks(streamer))

    network.script_info = _script_info
    network.code = network.symbol
    network.script_tools = scriptTools

    return network
