import binascii

from ..encoding import a2b_hashed_base58, EncodingError
from ..serialize import h2b
from ..contrib.segwit_addr import bech32_decode


def key_info_from_text(text, networks):
    try:
        data = a2b_hashed_base58(text)
        for network in networks:
            try:
                r = network.keyparser.key_info_from_b58(data)
                if r:
                    yield network, r
            except Exception:
                pass
    except EncodingError:
        pass

    try:
        hrp, data = bech32_decode(text)
        if hrp and data:
            for network in networks:
                try:
                    r = network.keyparser.key_info_from_bech32(hrp, data)
                    if r:
                        yield network, r
                except Exception:
                    pass
    except (TypeError, KeyError):
        pass

    try:
        prefix, rest = text.split(":", 1)
        data = h2b(rest)
        for network in networks:
            try:
                r = network.keyparser.key_info_from_prefixed_hex(prefix, data)
                if r:
                    yield network, r
            except Exception:
                pass
    except (binascii.Error, TypeError, ValueError):
        pass

    for network in networks:
        try:
            r = network.keyparser.key_info_from_plaintext(text)
            if r:
                yield network, r
        except Exception:
            pass


def key_from_text(text, generator=None, is_compressed=None, key_types=None):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

    The "is_compressed" parameter is ignored unless a public address is passed in.
    """
    from ..networks.registry import network_codes, network_for_netcode
    networks = [network_for_netcode(netcode) for netcode in network_codes()]
    for network, key_info in key_info_from_text(text, networks=networks):
        if is_compressed is not None:
            # THIS IS A STUPID HACK
            key_info["kwargs"]["is_compressed"] = is_compressed
        return key_info["key_class"](**key_info["kwargs"])

    raise EncodingError("unknown text: %s" % text)
