from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="BTX", network_name="BitCore", subnet_name="mainnet",
    wif_prefix_hex="80", sec_prefix="BTXSEC:", address_prefix_hex="03", pay_to_script_prefix_hex="7D",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="F9BEB4D9", default_port=8555,
    dns_bootstrap=[
        "seed.bitcore.biz"
    ])
