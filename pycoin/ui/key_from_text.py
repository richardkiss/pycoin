from pycoin.ui.Parser import metadata_for_text


def key_info_from_text(text, networks):
    metadata = metadata_for_text(text)
    for network in networks:
        info = network.ui.parse_to_info(metadata, types=["key", "bip32", "electrum"])
        if info:
            yield network, info


def key_from_text(text, key_types=None, networks=None):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

    The "is_compressed" parameter is ignored unless a public address is passed in.
    """
    from ..networks.registry import network_codes, network_for_netcode
    networks = networks or [network_for_netcode(netcode) for netcode in network_codes()]
    for network, key_info in key_info_from_text(text, networks=networks):
        return key_info["create_f"]()
    return None
