from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="AXE", network_name="Axe", subnet_name="mainnet",
    wif_prefix_hex="cc", address_prefix_hex="37", pay_to_script_prefix_hex="10",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
