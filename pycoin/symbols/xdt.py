from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="XDT", network_name="Dogecoin", subnet_name="testnet",
    wif_prefix_hex="f1", address_prefix_hex="71", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="0432a9a8", bip32_pub_prefix_hex="0432a243")
