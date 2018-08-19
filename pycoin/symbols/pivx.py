from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="PIVX", network_name="PIVX", subnet_name="mainnet",
    wif_prefix_hex="d4", address_prefix_hex="1e", pay_to_script_prefix_hex="0064",
    bip32_prv_prefix_hex="0221312b", bip32_pub_prefix_hex="022d2533")
