import re
import threading
import warnings

from .bitcoind import BitcoindProvider
from .blockexplorer import BlockExplorer
from .blockchain_info import BlockchainInfo
from .blockr_io import BlockrioProvider
from .chain_so import ChainSoProvider
from .insight import InsightService

from .env import main_cache_dir, config_string_for_netcode_from_env
from .env import tx_read_cache_dirs, tx_writable_cache_dir
from .tx_db import TxDb


THREAD_LOCALS = threading.local()


ALL_PROVIDERS = [
    BitcoindProvider, BlockExplorer, BlockchainInfo, BlockrioProvider, ChainSoProvider, InsightService]


# PYCOIN_BTC_PROVIDERS="blockchain.info blockexplorer.com blockr.io chain.so"
# PYCOIN_BTC_PROVIDERS="insight:http(s?)://hostname/url bitcoinrpc://user:passwd@hostname:8333"

class NoServicesSpecifiedError(Exception):
    pass


def service_provider_methods(method_name, service_providers):
    methods = [getattr(m, method_name, None) for m in service_providers]
    methods = [m for m in methods if m]
    return methods


def spendables_for_address(bitcoin_address, netcode, format=None):
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
    for m in service_provider_methods("spendables_for_address", providers_for_netcode_from_env(netcode)):
        try:
            spendables = m(bitcoin_address)
            if format:
                spendables = [getattr(s, method)() for s in spendables]
            return spendables
        except Exception:
            pass
    return []


def get_tx_db(netcode):
    lookup_methods = service_provider_methods("tx_for_tx_hash", providers_for_netcode_from_env(netcode))
    read_cache_dirs = tx_read_cache_dirs()
    writable_cache_dir = tx_writable_cache_dir()
    return TxDb(lookup_methods=lookup_methods, read_only_paths=read_cache_dirs,
                writable_cache_path=writable_cache_dir)


def message_about_tx_cache_env():
    if main_cache_dir() is None:
        return "consider setting environment variable PYCOIN_CACHE_DIR=~/.pycoin_cache to"\
               " cache transactions fetched via web services"


def all_providers_message(method, netcode):
    if len(service_provider_methods(method, providers_for_netcode_from_env(netcode))) == 0:
        return "no service providers found for %s; consider setting environment variable "\
            "PYCOIN_%s_PROVIDERS" % (method, netcode)


def message_about_spendables_for_address_env(netcode):
    return all_providers_message("spendables_for_address")


def message_about_tx_for_tx_hash_env(netcode):
    return all_providers_message("tx_for_tx_hash", netcode)


def bitcoin_rpc_init(match, netcode):
    username, password, hostname, port = match.group("user", "password", "hostname", "port")
    return BitcoindProvider("http://%s:%s@%s:%s" % (username, password, hostname, port))


def insight_init(match, netcode):
    return InsightService(base_url=match.group("url"))


def providers_for_config_string(config_string, netcode):
    providers = []
    for d in config_string.split():
        p = provider_for_descriptor_and_netcode(d, netcode)
        if p:
            providers.append(p)
        else:
            warnings.warn("can't parse provider %s in config string" % d)
    return providers


def providers_for_netcode_from_env(netcode):
    env_var = "PYCOIN_%s_PROVIDERS" % netcode
    return providers_for_config_string(config_string_for_netcode_from_env(netcode), netcode)


DESCRIPTOR_CRE_INIT_TUPLES = [
    (re.compile(
        r"^bitcoinrpc://(?P<user>\S*):(?P<password>\S*)\@(?P<hostname>\S*)(:(?P<port>\d*))"),
        bitcoin_rpc_init),
    (re.compile(r"^blockchain\.info$"), lambda m, netcode: BlockchainInfo(netcode)),
    (re.compile(r"^blockexplorer\.com$"), lambda m, netcode: BlockExplorer(netcode)),
    (re.compile(r"^blockr\.io$"), lambda m, netcode: BlockrioProvider(netcode)),
    (re.compile(r"^chain\.so$"), lambda m, netcode: ChainSoProvider(netcode)),
    (re.compile(r"^insight:(?P<url>\S*)$"), insight_init),
]


def provider_for_descriptor_and_netcode(descriptor, netcode="BTC"):
    # methods:
    # get_block_for_hash
    # get_tx_for_hash
    # get_blockchain_tip
    # send_tx
    # spendables_for_address
    for cre, f in DESCRIPTOR_CRE_INIT_TUPLES:
        m = cre.match(descriptor)
        if m:
            return f(m, netcode)
    return None


def get_default_providers_for_netcode(netcode="BTC"):
    if not hasattr(THREAD_LOCALS, "providers"):
        THREAD_LOCALS.providers = {}
    if netcode not in THREAD_LOCALS.providers:
        THREAD_LOCALS.providers[netcode] = providers_for_netcode_from_env(netcode)
    return THREAD_LOCALS.providers[netcode]


def set_default_providers_for_netcode(netcode, provider_list):
    if not hasattr(THREAD_LOCALS, "providers"):
        THREAD_LOCALS.providers = {}
    THREAD_LOCALS.providers[netcode] = provider_list
