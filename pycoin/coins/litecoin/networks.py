from pycoin.networks.bitcoinish import create_bitcoinish_network


LitecoinMainnet = create_bitcoinish_network(
    network_name="Litecoin", netcode="LTC", subnet_name="mainnet",
    wif_prefix_hex="b0", sec_prefix="LTCSEC:", address_prefix_hex="30", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="019d9cfe", bip32_pub_prefix_hex="019da462", bech32_hrp="lc")


LitecoinTestnet = create_bitcoinish_network(
    network_name="Litecoin", netcode="XLT", subnet_name="testnet",
    wif_prefix_hex="ef", sec_prefix="XLTSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="0436ef7d", bip32_pub_prefix_hex="0436f6e1", bech32_hrp="tl")
