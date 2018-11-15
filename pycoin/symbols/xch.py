from pycoin.networks.bitcoinish import create_bitcoinish_network

from pycoin.coins.bcash.Tx import Tx as BcashTx


network = create_bitcoinish_network(
    symbol="XCH", network_name="Bcash", subnet_name="testnet3", tx=BcashTx,
    wif_prefix_hex="ef", sec_prefix="XCHSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587CF", bech32_hrp="tb",
    magic_header_hex="0B110907", default_port=18333,
    dns_bootstrap=[
        "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
        "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
        "seed.deadalnix.me", "seeder.criptolayer.net"
    ])
