import importlib
import random

from .env import main_cache_dir, service_providers_for_env, tx_read_cache_dirs, tx_writable_cache_dir
from .tx_db import TxDb


SERVICE_PROVIDERS = ["BLOCKCHAIN_INFO", "BLOCKEXPLORER", "BLOCKR_IO", "BITEASY"]


class NoServicesSpecifiedError(Exception):
    pass


def service_provider_methods(method_name, service_providers):
    modules = [importlib.import_module("pycoin.services.%s" % p.lower())
               for p in service_providers if p in SERVICE_PROVIDERS]
    methods = [getattr(m, method_name, None) for m in modules]
    methods = [m for m in methods if m]
    return methods


def spendables_for_address(bitcoin_address, format=None):
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
    for m in service_provider_methods("spendables_for_address", service_providers_for_env()):
        try:
            spendables = m(bitcoin_address)
            if format:
                spendables = [getattr(s, method)() for s in spendables]
            return spendables
        except Exception:
            pass
    return []


def get_tx_db():
    lookup_methods = service_provider_methods("get_tx", service_providers_for_env())
    read_cache_dirs = tx_read_cache_dirs()
    writable_cache_dir = tx_writable_cache_dir()
    return TxDb(lookup_methods=lookup_methods, read_only_paths=read_cache_dirs,
                writable_cache_path=writable_cache_dir)


def message_about_tx_cache_env():
    if main_cache_dir() is None:
        return "consider setting environment variable PYCOIN_CACHE_DIR=~/.pycoin_cache to"\
               " cache transactions fetched via web services"


def all_providers_message(method):
    if len(service_provider_methods(method, service_providers_for_env())) == 0:
        l = list(SERVICE_PROVIDERS)
        random.shuffle(l)
        return "no service providers found for %s; consider setting environment variable "\
            "PYCOIN_SERVICE_PROVIDERS=%s" % (method, ':'.join(l))


def message_about_spendables_for_address_env():
    return all_providers_message("spendables_for_address")


def message_about_get_tx_env():
    return all_providers_message("get_tx")
