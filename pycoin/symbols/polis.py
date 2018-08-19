from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    symbol="POLIS", network_name="Polis", subnet_name="mainnet",
    wif_prefix_hex="3C", address_prefix_hex="37", pay_to_script_prefix_hex="3C",
    bip32_prv_prefix_hex="03e25d7e", bip32_pub_prefix_hex="03e25945",
    magic_header_hex="BD6B0CBF", default_port=24126,
    dns_bootstrap=[
        "dnsseed.poliscentral.org", "dnsseed2.poliscentral.org",
        "dnsseed3.poliscentral.org", "polis.seeds.mn.zone", "polis.mnseeds.com"
    ])
