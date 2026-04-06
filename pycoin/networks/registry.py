from __future__ import annotations

import importlib
import os
import pkgutil
from typing import Any, Iterator


def search_prefixes() -> list[str]:
    prefixes = ["pycoin.symbols"]
    try:
        prefixes = os.getenv("PYCOIN_NETWORK_PATHS", "").split() + prefixes
    except Exception:
        pass
    return prefixes


def network_for_netcode(symbol: str) -> Any:
    symbol = symbol.upper()
    netcode = symbol.lower()
    for prefix in search_prefixes():
        try:
            module = importlib.import_module("%s.%s" % (prefix, netcode))
            if module.network.symbol.upper() == symbol:
                module.symbol = symbol  # type: ignore[attr-defined]
                return module.network
        except (AttributeError, ImportError):
            pass
    raise ValueError("no network with symbol %s found" % netcode)


def iterate_symbols() -> Iterator[Any]:
    """
    Return an iterator yielding registered netcodes.
    """
    for prefix in search_prefixes():
        package = importlib.import_module(prefix)
        for importer, modname, ispkg in pkgutil.walk_packages(
            path=package.__path__, onerror=lambda x: None
        ):
            network = network_for_netcode(modname)
            if network:
                yield network.symbol.upper()


def network_codes() -> list[Any]:
    return list(iterate_symbols())
