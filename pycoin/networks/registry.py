import importlib
import os
import pkgutil


def search_prefixes():
    prefixes = ["pycoin.symbols"]
    try:
        prefixes = os.getenv("PYCOIN_NETWORK_PATHS", "").split() + prefixes
    except Exception:
        pass
    return prefixes


def network_for_netcode(symbol):
    symbol = symbol.upper()
    netcode = symbol.lower()
    for prefix in search_prefixes():
        try:
            module = importlib.import_module("%s.%s" % (prefix, netcode))
            if module.network.symbol.upper() == symbol:
                module.symbol = symbol
                return module.network
        except (AttributeError, ImportError):
            pass
    raise ValueError("no network with symbol %s found" % netcode)


def iterate_symbols():
    """
    Return an iterator yielding registered netcodes.
    """
    for prefix in search_prefixes():
        package = importlib.import_module(prefix)
        for importer, modname, ispkg in pkgutil.walk_packages(path=package.__path__, onerror=lambda x: None):
            network = network_for_netcode(modname)
            if network:
                yield network.symbol.upper()


def network_codes():
    return list(iterate_symbols())
