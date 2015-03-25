
import binascii

MAINNET = dict(
    MAGIC_HEADER=binascii.unhexlify('F9BEB4D9'),
    DNS_BOOTSTRAP=[
        "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org"
        "bitseed.xf2.org", "dnsseed.bluematt.me",
    ]
)

TESTNET = dict(
    MAGIC_HEADER=binascii.unhexlify('0B110907'),
    DNS_BOOTSTRAP=[
        "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
        "bluematt.me", "testnet-seed.bluematt.me"
    ]
)
