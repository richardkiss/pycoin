from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="BTDX", network_name="Bitcloud", subnet_name="mainnet",
    wif_prefix_hex="99", sec_prefix="BTDXSEC:", address_prefix_hex="19", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="E4E8BDFD", default_port=8329,
    dns_bootstrap=[
        "seed.bitcloud.network"
    ])
