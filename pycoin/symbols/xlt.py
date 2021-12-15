from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    network_name="Litecoin", symbol="XLT", subnet_name="testnet",
    wif_prefix_hex="ef", sec_prefix="XLTSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="3a",
    bip32_prv_prefix_hex="0436ef7d", bip32_pub_prefix_hex="0436f6e1", bech32_hrp="tltc")
