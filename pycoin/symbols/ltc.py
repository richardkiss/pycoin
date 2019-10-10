from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    network_name="Litecoin", symbol="LTC", subnet_name="mainnet",
    wif_prefix_hex="b0", sec_prefix="LTCSEC:", address_prefix_hex="30", pay_to_script_prefix_hex="32",
    bip32_prv_prefix_hex="019d9cfe", bip32_pub_prefix_hex="019da462", bech32_hrp="ltc")
