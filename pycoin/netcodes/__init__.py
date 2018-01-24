import os

from importlib import import_module


def network_for_netcode(netcode):
    netcode = netcode.lower()
    prefixes = ["pycoin.netcodes"]
    try:
        prefixes = os.getenv("PYCOIN_PROVIDERS_PATH", "").split() + prefixes
    except Exception:
        pass
    for prefix in prefixes:
        try:
            module = import_module("%s.%s" % (prefix, netcode))
            return module.network
        except ModuleNotFoundError:
            pass
