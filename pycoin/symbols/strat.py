from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="STRAT", network_name="Strat", subnet_name="mainnet",
    wif_prefix_hex="bf", sec_prefix="STRATSEC:", address_prefix_hex="3f", pay_to_script_prefix_hex="7d",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    default_port=16178)
