from pycoin.ui.Parser import parseable_str


def network_key_from_text(text, networks=None):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.
    """
    from ..networks.registry import network_codes, network_for_netcode
    text = parseable_str(text)
    networks = networks or [network_for_netcode(netcode) for netcode in network_codes()]
    for network in networks:
        v = (network.parse.wif(text) or network.parse.bip32_prv(text) or
             network.parse.bip32_pub(text) or network.parse.bip32_seed(text) or
             network.parse.electrum_seed(text) or network.parse.electrum_prv(text) or
             network.parse.electrum_pub(text) or network.parse.address(text))
        if v:
            return network, v
    return None, None


def key_from_text(text, networks=None):
    v = network_key_from_text(text, networks)
    if v:
        return v[1]
