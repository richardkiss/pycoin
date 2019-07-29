from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    network_name="Digibyte", symbol="DGB", subnet_name="mainnet",
    wif_prefix_hex="b0", sec_prefix="DGBSEC:", address_prefix_hex="1E", pay_to_script_prefix_hex="3F",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E", bech32_hrp="dgb")
