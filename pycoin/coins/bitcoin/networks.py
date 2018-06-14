from pycoin.networks.bitcoinish import create_bitcoinish_network


# fork at block 491407

BitcoinMainnet = create_bitcoinish_network(
    netcode="BTC", network_name="Bitcoin", subnet_name="mainnet",
    wif_prefix_hex="80", sec_prefix="BTCSEC:", address_prefix_hex="00", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E", bech32_hrp="bc",
    magic_header_hex="F9BEB4D9", default_port=8333,
    dns_bootstrap=[
        "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org", "dnsseed.bluematt.me",
    ])


BitcoinTestnet = create_bitcoinish_network(
    netcode="XTN", network_name="Bitcoin", subnet_name="testnet3",
    wif_prefix_hex="ef", sec_prefix="XTNSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587CF", bech32_hrp="tb",
    magic_header_hex="0B110907", default_port=18333,
    dns_bootstrap=[
        "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
        "bluematt.me", "testnet-seed.bluematt.me"
    ])


BitcoinRegtest = create_bitcoinish_network(
    netcode="XRT", network_name="Bitcoin", subnet_name="regtest",
    wif_prefix_hex="ef", sec_prefix="XTNSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587CF", bech32_hrp="bcrt",
    magic_header_hex="0B110907", default_port=18444)
