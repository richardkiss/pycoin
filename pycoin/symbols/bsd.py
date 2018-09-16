from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="BSD", network_name="BitSend", subnet_name="mainnet",
    wif_prefix_hex="CC", sec_prefix="BSDSEC:", address_prefix_hex="66", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="A3D5C2F9", default_port=8886,
    dns_bootstrap=[
        "seed.mybitsend.com"
    ])
