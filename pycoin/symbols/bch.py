from pycoin.coins.bcash.Tx import Tx as BcashTx
from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    symbol="BCH", network_name="Bcash", subnet_name="mainnet", tx=BcashTx,
    wif_prefix_hex="80", sec_prefix="BCHSEC:", address_prefix_hex="00", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="F9BEB4D9", default_port=8333,
    dns_bootstrap=[
        "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
        "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
        "seed.deadalnix.me", "seeder.criptolayer.net"
    ])
