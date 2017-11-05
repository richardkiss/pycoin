import binascii
from .. import encoding
from ..intbytes import int2byte
from ..serialize import h2b
from ..coins.bitcoin.ScriptTools import BitcoinScriptTools, IntStreamer
from ..contrib.segwit_addr import bech32_decode, convertbits

from pycoin.ui.uiclass import metadata_for_text

DEFAULT_ADDRESS_TYPES = ["p2pkh", "p2sh"]


def network_for_netcodes(netcodes):
    from ..networks.registry import network_codes, network_for_netcode
    if netcodes is None:
        netcodes = network_codes()
    return [network_for_netcode(netcode) for netcode in netcodes]


def is_address_valid(address, allowable_types=DEFAULT_ADDRESS_TYPES, allowable_netcodes=None):
    """
    Accept an address, and a list of allowable address types (a subset of "address" and "pay_to_script"),
    and allowable networks (defaulting to just Bitcoin mainnet), return the network that the address is
    a part of, or None if it doesn't validate.
    """
    networks = network_for_netcodes(allowable_netcodes)
    metadata = metadata_for_text(address)
    for network in networks:
        k = network.ui.parse_metadata_to_info(metadata, types=["address"])
        if k:
            if k["info"]["subtype"] in allowable_types:
                return network.code
    return None


def _is_key_valid(text, allowable_netcodes, info_filter_f):
    networks = network_for_netcodes(allowable_netcodes)
    metadata = metadata_for_text(text)
    for network in networks:
        k = network.ui.parse_metadata_to_info(metadata, types=["key"])
        if k:
            if info_filter_f(k):
                return network.code
    return None


def is_wif_valid(wif, allowable_netcodes=None):
    """
    Accept a WIF, and a list of allowable networks (defaulting to just Bitcoin mainnet), return
    the network that the wif is a part of, or None if it doesn't validate.
    """

    def info_filter_f(k):
        return k["info"]["key_type"] == 'wif'

    return _is_key_valid(wif, allowable_netcodes, info_filter_f)


def is_public_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 public wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """

    def info_filter_f(k):
        return k["info"]["key_type"] == 'bip32' and k["info"]["is_private"] == False

    return _is_key_valid(hwif, allowable_netcodes, info_filter_f)


def is_private_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 private wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    def info_filter_f(k):
        return k["info"]["key_type"] == 'bip32' and k["info"]["is_private"] == True

    return _is_key_valid(hwif, allowable_netcodes, info_filter_f)
