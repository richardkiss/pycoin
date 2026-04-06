from __future__ import annotations

import re
import threading
import warnings
from typing import Any

from pycoin.networks.default import get_current_netcode

from .bitcoind import BitcoindProvider
from .blockexplorer import BlockExplorerProvider
from .blockchain_info import BlockchainInfoProvider
from .blockcypher import BlockcypherProvider
from .chain_so import ChainSoProvider
from .insight import InsightProvider
from .btgexp import BTGExpProvider

from .env import main_cache_dir, config_string_for_netcode_from_env
from .env import tx_read_cache_dirs, tx_writable_cache_dir
from .tx_db import TxDb


THREAD_LOCALS = threading.local()


# PYCOIN_BTC_PROVIDERS="blockchain.info blockexplorer.com blockcypher.com chain.so"
# PYCOIN_BTC_PROVIDERS="insight:http(s?)://hostname/url bitcoinrpc://user:passwd@hostname:8332"


def service_provider_methods(method_name: str, service_providers: list[Any]) -> list[Any]:
    methods = [getattr(m, method_name, None) for m in service_providers]
    methods = [m for m in methods if m]
    return methods


def spendables_for_address(address: str, netcode: str, format: str | None = None) -> list[Any]:
    """
    Return a list of Spendable objects for the
    given bitcoin address.

    Set format to "text" or "dict" to transform return value
    from an object to a string or dict.

    This is intended to be a convenience function. There is no way to know that
    the list returned is a complete list of spendables for the address in question.

    You can verify that they really do come from the existing transaction
    by calling tx_utils.validate_unspents.
    """
    if format:
        method = "as_%s" % format
    for m in service_provider_methods(
        "spendables_for_address", get_default_providers_for_netcode(netcode)
    ):
        try:
            spendables = m(address)
            if format:
                spendables = [getattr(s, method)() for s in spendables]
            return spendables  # type: ignore[no-any-return]
        except Exception:
            pass
    return []


def get_tx_db(netcode: str | None = None) -> Any:
    lookup_methods = service_provider_methods(
        "tx_for_tx_hash", get_default_providers_for_netcode(netcode)
    )
    read_cache_dirs = tx_read_cache_dirs()
    writable_cache_dir = tx_writable_cache_dir()
    return TxDb(
        lookup_methods=lookup_methods,
        read_only_paths=read_cache_dirs,
        writable_cache_path=writable_cache_dir,
    )


def message_about_tx_cache_env() -> str | None:
    if main_cache_dir() is None:
        return (
            "consider setting environment variable PYCOIN_CACHE_DIR=~/.pycoin_cache to"
            " cache transactions fetched via web services"
        )
    return None


def all_providers_message(method: str, netcode: str) -> str | None:
    if (
        len(
            service_provider_methods(method, get_default_providers_for_netcode(netcode))
        )
        == 0
    ):
        return (
            "no service providers found for %s; consider setting environment variable "
            "PYCOIN_%s_PROVIDERS" % (method, netcode)
        )
    return None


def message_about_spendables_for_address_env(netcode: str) -> str | None:
    return all_providers_message("spendables_for_address", netcode)


def message_about_tx_for_tx_hash_env(netcode: str) -> str | None:
    return all_providers_message("tx_for_tx_hash", netcode)


def bitcoin_rpc_init(match: re.Match[str], netcode: str) -> BitcoindProvider:
    username, password, hostname, port = match.group(
        "user", "password", "hostname", "port"
    )
    return BitcoindProvider("http://%s:%s@%s:%s" % (username, password, hostname, port))


def insight_init(match: re.Match[str], netcode: str) -> InsightProvider:
    return InsightProvider(base_url=match.group("url"), netcode=netcode)


DESCRIPTOR_CRE_INIT_TUPLES = [
    (
        re.compile(
            r"^bitcoinrpc://(?P<user>\S*):(?P<password>\S*)\@(?P<hostname>\S*)(:(?P<port>\d*))"
        ),
        bitcoin_rpc_init,
    ),
    (
        re.compile(r"^blockchain\.info$"),
        lambda m, netcode: BlockchainInfoProvider(netcode),
    ),
    (
        re.compile(r"^blockcypher\.com$"),
        lambda m, netcode: BlockcypherProvider(netcode),
    ),
    (
        re.compile(r"^blockexplorer\.com$"),
        lambda m, netcode: BlockExplorerProvider(netcode),
    ),
    (re.compile(r"^chain\.so$"), lambda m, netcode: ChainSoProvider(netcode)),
    (re.compile(r"^insight:(?P<url>\S*)$"), insight_init),
    (re.compile(r"^btgexp.com"), lambda m, netcode: BTGExpProvider()),
]


def provider_for_descriptor_and_netcode(descriptor: str, netcode: str | None = None) -> Any:
    if netcode is None:
        netcode = get_current_netcode()
    for cre, f in DESCRIPTOR_CRE_INIT_TUPLES:
        m = cre.match(descriptor)
        if m:
            return f(m, netcode)
    return None


def providers_for_config_string(config_string: str, netcode: str) -> list[Any]:
    providers: list[Any] = []
    for d in config_string.split():
        p = provider_for_descriptor_and_netcode(d, netcode)
        if p:
            providers.append(p)
        else:
            warnings.warn("can't parse provider %s in config string" % d)
    return providers


def providers_for_netcode_from_env(netcode: str) -> list[Any]:
    return providers_for_config_string(
        config_string_for_netcode_from_env(netcode), netcode
    )


def get_default_providers_for_netcode(netcode: str | None = None) -> list[Any]:
    if netcode is None:
        netcode = get_current_netcode()
    if not hasattr(THREAD_LOCALS, "providers"):
        THREAD_LOCALS.providers = {}
    if netcode not in THREAD_LOCALS.providers:
        THREAD_LOCALS.providers[netcode] = providers_for_netcode_from_env(netcode)
    return THREAD_LOCALS.providers[netcode]  # type: ignore[no-any-return]


def set_default_providers_for_netcode(netcode: str, provider_list: list[Any]) -> None:
    if not hasattr(THREAD_LOCALS, "providers"):
        THREAD_LOCALS.providers = {}
    THREAD_LOCALS.providers[netcode] = provider_list
