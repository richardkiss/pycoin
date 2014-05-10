
from .. import encoding
from .. import networks

DEFAULT_NETCODES = ["BTC"]


def _check_against(text, expected_type, allowable_netcodes):
    try:
        data = encoding.a2b_hashed_base58(text)
        netcode, the_type = networks.netcode_and_type_for_data(data)
        if the_type in expected_type and netcode in allowable_netcodes:
            return netcode
    except encoding.EncodingError:
        pass
    return None


def is_address_valid(address, allowable_types=["address", "pay_to_script"], allowable_netcodes=DEFAULT_NETCODES):
    return _check_against(address, allowable_types, allowable_netcodes)


def is_wif_valid(wif, allowable_netcodes=DEFAULT_NETCODES):
    return _check_against(wif, ["wif"], allowable_netcodes)


def is_public_bip32_valid(hwif, allowable_netcodes=DEFAULT_NETCODES):
    return _check_against(hwif, ["pub32"], allowable_netcodes)


def is_private_bip32_valid(hwif, allowable_netcodes=DEFAULT_NETCODES):
    return _check_against(hwif, ["prv32"], allowable_netcodes)
