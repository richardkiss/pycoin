from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="RIC", network_name="Riecoin", subnet_name="mainnet",
    wif_prefix_hex="80", address_prefix_hex="3c", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
