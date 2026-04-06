from __future__ import annotations

import os
import threading
from typing import Any

from .registry import network_for_netcode

THREAD_LOCALS = threading.local()


def check_netcode(netcode: str) -> None:
    if network_for_netcode(netcode) is None:
        raise ValueError("unknown netcode %s" % netcode)


def _netcode_for_env() -> str:
    p = os.getenv("PYCOIN_DEFAULT_NETCODE")
    if p is None:
        p = "BTC"
    check_netcode(p)
    return p


DEFAULT_NETCODE = _netcode_for_env()


def set_default_netcode(netcode: str) -> None:
    global DEFAULT_NETCODE
    check_netcode(netcode)
    DEFAULT_NETCODE = netcode


def set_default_netcode_for_thread(netcode: str) -> None:
    check_netcode(netcode)
    THREAD_LOCALS.netcode = netcode


def get_current_netcode() -> str:
    # check the thread local first
    # if that doesn't exist, use the global default
    return getattr(THREAD_LOCALS, "netcode", DEFAULT_NETCODE)


def get_current_network() -> Any:
    return network_for_netcode(get_current_netcode())
