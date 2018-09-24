from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="MEC", network_name="Megacoin", subnet_name="mainnet",
    wif_prefix_hex="B2", sec_prefix="MECSEC:", address_prefix_hex="32", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="EDE0E4EE", default_port=7951,
    dns_bootstrap=[]
)
