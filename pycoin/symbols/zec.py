from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="ZEC", network_name="Zcash", subnet_name="mainnet",
    wif_prefix_hex="80", address_prefix_hex="1cb8", pay_to_script_prefix_hex="1cbd",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
