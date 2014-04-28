import os


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
