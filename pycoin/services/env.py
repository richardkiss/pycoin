import os
import warnings


def service_providers_for_env():
    return os.getenv("PYCOIN_SERVICE_PROVIDERS", '').split(":")


def main_cache_dir():
    p = os.getenv("PYCOIN_CACHE_DIR")
    if p:
        p = os.path.expanduser(p)
    return p


def tx_read_cache_dirs():
    return [p for p in os.getenv("PYCOIN_TX_DB_DIRS", "").split(":") if len(p) > 0]


def tx_writable_cache_dir():
    p = main_cache_dir()
    if p:
        p = os.path.join(main_cache_dir(), "txs")
    return p


def providers_for_netcode_from_env(netcode):
    providers = []
    env_var = "PYCOIN_%s_PROVIDERS" % netcode
    env_val = os.getenv(env_var)
    for d in env_val.split():
        p = provider_for_descriptor_and_netcode(d, netcode)
        if p:
            providers.append(p)
        else:
            warnings.warn("can't parse %s in environment variable %s" % (d, env_code))
    return providers
