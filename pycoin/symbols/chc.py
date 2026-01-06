from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="CHC", network_name="Chaincoin", subnet_name="mainnet",
    wif_prefix_hex="9c", address_prefix_hex="1c", pay_to_script_prefix_hex="04",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
