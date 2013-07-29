
import decimal

SATOSHI_PER_COIN = decimal.Decimal(1e8)
COIN_PER_SATOSHI = decimal.Decimal(1e-8)

def satoshi_to_btc(satoshi_count):
    return satoshi_count * COIN_PER_SATOSHI

def btc_to_satoshi(btc):
    return int(btc * SATOSHI_PER_COIN)
