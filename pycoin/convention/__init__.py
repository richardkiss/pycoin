
import decimal

SATOSHI_PER_COIN = decimal.Decimal(int(1e8))
COIN_PER_SATOSHI = decimal.Decimal(1)/SATOSHI_PER_COIN

SATOSHI_TO_MBTC = decimal.Decimal(int(1e5))
MBTC_PER_SATOSHI = 1/SATOSHI_TO_MBTC


def satoshi_to_btc(satoshi_count):
    if satoshi_count == 0:
        return decimal.Decimal(0)
    r = satoshi_count * COIN_PER_SATOSHI
    return r.quantize(COIN_PER_SATOSHI)


def btc_to_satoshi(btc):
    return int(decimal.Decimal(btc) * SATOSHI_PER_COIN)


def satoshi_to_mbtc(satoshi_count):
    if satoshi_count == 0:
        return decimal.Decimal(0)
    r = satoshi_count / SATOSHI_TO_MBTC
    return r.quantize(MBTC_PER_SATOSHI)


def mbtc_to_satoshi(btc):
    return int(decimal.Decimal(btc) * SATOSHI_TO_MBTC)
