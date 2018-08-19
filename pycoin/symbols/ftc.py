from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="FTC", network_name="Feathercoin", subnet_name="mainnet",
    wif_prefix_hex="8e", address_prefix_hex="0e", pay_to_script_prefix_hex="60",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
