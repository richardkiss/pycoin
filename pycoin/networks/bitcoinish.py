from pycoin.block import Block
from pycoin.coins.bitcoin.extras import Extras
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer, standard_messages,
    standard_message_post_unpacks, standard_streamer, standard_parsing_functions
)
from pycoin.encoding.hexbytes import h2b
from pycoin.ui.uiclass import UI
from pycoin.vm.ScriptInfo import ScriptInfo


DEFAULT_ARGS_ORDER = (
    'code', 'network_name', 'subnet_name',
    'tx', 'block',
    'magic_header', 'default_port', 'dns_bootstrap',
    'ui', 'extras'
)


class Network(object):
    def __init__(self, *args, **kwargs):
        for arg, name in zip(args, DEFAULT_ARGS_ORDER):
            kwargs[name] = arg
        for k, v in kwargs.items():
            if k not in DEFAULT_ARGS_ORDER:
                raise TypeError("unexpected argument %s" % k)
        for name in DEFAULT_ARGS_ORDER:
            setattr(self, name, kwargs.get(name, None))

    def full_name(self):
        return "%s %s" % (self.network_name, self.subnet_name)

    def __repr__(self):
        return "<Network %s %s>" % (self.network_name, self.subnet_name)


def create_bitcoinish_network(**kwargs):
    # potential kwargs:
    #   netcode, network_name, subnet_name, tx, block, magic_header_hex, default_port, dns_bootstrap,
    #   wif_prefix_hex, address_prefix_hex, pay_to_script_prefix_hex
    #   bip32_prv_prefix_hex, bip32_pub_prefix_hex, sec_prefix, scriptTools

    generator = kwargs.get("generator", secp256k1_generator)
    kwargs.setdefault("sec_prefix", "%sSEC" % kwargs["netcode"].upper())
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
    ui = UI(_script_info, kwargs.get("generator", generator), **ui_kwargs)
    extras = Extras(scriptTools, ui)
    kwargs["ui"] = ui
    kwargs["extras"] = extras
    kwargs.setdefault("tx", Tx)
    kwargs.setdefault("block", Block.make_subclass(kwargs["tx"]))

    NETWORK_KEYS = ("network_name subnet_name tx block ui extras "
                    "dns_bootstrap default_port magic_header").split()
    network_kwargs = {k: kwargs.get(k) for k in NETWORK_KEYS if k in kwargs}
    network_kwargs["code"] = kwargs["netcode"]  # BRAIN DAMAGE
    network = Network(**network_kwargs)

    streamer = standard_streamer(standard_parsing_functions(network.block, network.tx))
    network.parse_message, network.pack_message = make_parser_and_packer(
        streamer, standard_messages(), standard_message_post_unpacks(streamer))

    return network
