
import binascii
from .. import encoding
from ..intbytes import byte2int, int2byte
from ..networks.registry import network_codes, network_prefixes, bech32_prefixes
from ..serialize import h2b
from ..contrib.segwit_addr import bech32_decode, convertbits
from pycoin.tx.script.tools import bin_script

DEFAULT_ADDRESS_TYPES = ["address", "pay_to_script"]


def netcode_and_type_lookup_for_data(data):
    """
    Given some already-decoded raw data from a base58 string,
    return a dictionary lookup from network codes to (T, L)
    where T is the key type ("wif", "address", "public_pair", "prv32", "pub32")
    and L is the length
    """
    prefixes = network_prefixes()
    sizes = set(len(p) for p in prefixes)
    d = {}
    for length in sizes:
        for netcode, the_type in prefixes.get(data[:length], []):
            d[netcode] = (the_type, length)
    return d


def netcode_and_type_for_data(data, netcodes=None):
    """
    Given some already-decoded raw data from a base58 string,
    return (N, T, L) where N is the network code ("BTC" or "LTC") and
    T is the key type, and L is the length of the prefix found.
    The netcodes are checked in order.
    May also raise EncodingError if no prefix found.
    """
    d = netcode_and_type_lookup_for_data(data)
    if netcodes is None:
        netcodes = network_codes()
    for netcode in netcodes:
        v = d.get(netcode)
        if v:
            return netcode, v[0], v[1]

    raise encoding.EncodingError("unknown prefix")


def netcode_and_type_for_text(text, netcodes=None):
    # check for "public pair"
    try:
        LENGTH_LOOKUP = {
            33: "public_pair",
            65: "public_pair",
            16: "elc_seed",
            32: "elc_prv",
            64: "elc_pub",
        }
        as_bin = h2b(text)
        l = len(as_bin)
        if l in LENGTH_LOOKUP:
            return None, LENGTH_LOOKUP[l], as_bin
    except (binascii.Error, TypeError):
        pass

    try:
        hrp, data = bech32_decode(text)
        decoded = convertbits(data[1:], 5, 8, False)
        script = bin_script([int2byte(data[0]), b''.join(int2byte(d) for d in decoded)])
        l = bech32_prefixes().get(hrp, [])
        if netcodes is None:
            netcodes = network_codes()
        for netcode in netcodes:
            if netcode in l:
                return netcode, "segwit", script
    except (TypeError, KeyError):
        pass

    data = encoding.a2b_hashed_base58(text)
    netcode, the_type, length = netcode_and_type_for_data(data, netcodes=netcodes)
    return netcode, the_type, data[length:]


def _check_against(text, expected_type, allowable_netcodes):
    if allowable_netcodes is None:
        allowable_netcodes = network_codes()
    try:
        netcode, the_type, data = netcode_and_type_for_text(text, netcodes=allowable_netcodes)
        if the_type in expected_type and netcode in allowable_netcodes:
            return netcode
    except encoding.EncodingError:
        pass
    return None


def is_address_valid(address, allowable_types=DEFAULT_ADDRESS_TYPES, allowable_netcodes=None):
    """
    Accept an address, and a list of allowable address types (a subset of "address" and "pay_to_script"),
    and allowable networks (defaulting to just Bitcoin mainnet), return the network that the address is
    a part of, or None if it doesn't validate.
    """
    return _check_against(address, allowable_types, allowable_netcodes)


def is_wif_valid(wif, allowable_netcodes=None):
    """
    Accept a WIF, and a list of allowable networks (defaulting to just Bitcoin mainnet), return
    the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(wif, ["wif"], allowable_netcodes)


def is_public_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 public wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(hwif, ["pub32"], allowable_netcodes)


def is_private_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 private wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(hwif, ["prv32"], allowable_netcodes)
