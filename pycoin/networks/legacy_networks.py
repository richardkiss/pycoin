# this file is deprecated and will soon be folded into all.py


from collections import namedtuple

from pycoin.serialize import h2b

NetworkValues = namedtuple('NetworkValues',
                           ('network_name', 'subnet_name', 'code', 'wif', 'address',
                            'pay_to_script', 'prv32', 'pub32'))

NETWORKS = (
    # LTC litecoin mainnet : Ltpv/Ltub
    NetworkValues("Litecoin", "mainnet", "LTC", b'\xb0', b'\x30', b'\5', h2b('019d9cfe'), h2b('019da462')),
    # LTC litecoin testnet : ttpv/ttub
    NetworkValues("Litecoin", "testnet", "XLT", b'\xef', b'\x6f', b'\xc4',
                  h2b('0436ef7d'), h2b('0436f6e1')),

    # VIA viacoin mainnet : xprv/xpub
    NetworkValues("Viacoin", "mainnet", "VIA", b'\xc7', b'\x47', b'\x21', h2b('0488ADE4'), h2b('0488B21E')),
    # VIA viacoin testnet : tprv/tpub
    NetworkValues("Viacoin", "testnet", "TVI", b'\xff', b'\x7f', b'\xc4', h2b('04358394'), h2b('043587CF')),

    # FTC feathercoin mainnet : xprv/xpub
    NetworkValues(
        "Feathercoin", "mainnet", "FTC", b'\x8e', b'\x0e', b'\x60', h2b('0488ADE4'), h2b('0488B21E')),
    # FTC feathercoin testnet : tprv/tpub
    NetworkValues(
        "Feathercoin", "testnet", "FTX", b'\xC1', b'\x41', b'\xc4', h2b('04358394'), h2b('043587CF')),

    # DOGE Dogecoin mainnet : dogv/dogp
    NetworkValues(
        "Dogecoin", "mainnet", "DOGE", b'\x9e', b'\x1e', b'\x16', h2b("02FD3955"), h2b("02FD3929")),
    # DOGE Dogecoin testnet : tgpv/tgub
    NetworkValues(
        "Dogecoin", "testnet", "XDT", b'\xf1', b'\x71', b'\xc4', h2b("0432a9a8"), h2b("0432a243")),


    # BC BlackCoin mainnet : bcpv/bcpb
    NetworkValues("Blackcoin", "mainnet", "BC", b'\x99', b'\x19', None, h2b("02cfbf60"), h2b("02cfbede")),

    # DRK Dash mainnet : drkv/drkp
    NetworkValues(
        "Dash", "mainnet", "DASH", b'\xcc', b'\x4c', b'\x10', h2b("02fe52f8"), h2b("02fe52cc")),

    # DRK Dash testnet : DRKV/DRKP
    NetworkValues(
        "Dash", "testnet", "tDASH", b'\xef', b'\x8c', b'\x13', h2b("3a8061a0"), h2b("3a805837")),

    # MEC Megacoin mainnet : mecv/mecp
    NetworkValues("Megacoin", "mainnet", "MEC", b'\xb2', b'\x32', None, h2b("03a04db7"), h2b("03a04d8b")),

    NetworkValues(
        "Myriadcoin", "mainnet", "MYR", b'\xb2', b'\x32', b'\x09', h2b('0488ADE4'), h2b('0488B21E')),

    NetworkValues(
        "Unobtanium", "mainnet", "UNO", b'\xe0', b'\x82', b'\x1e', h2b('0488ADE4'), h2b('0488B21E')),

    # JBS Jumbucks mainnet : jprv/jpub
    NetworkValues("Jumbucks", "mainnet", "JBS", b'\xab', b'\x2b', None, h2b('037a6460'), h2b('037a689a')),

    # MZC Mazacoin mainnet: xprv/xpub
    NetworkValues("Mazacoin", "mainnet", "MZC", b'\xe0', b'\x32', b'\9', h2b("0488ADE4"), h2b("0488B21E")),

    NetworkValues(
        "Riecoin", "mainnet", "RIC", b'\x80', b'\x3c', b'\x05', h2b('0488ADE4'), h2b('0488B21E')),

    # DFC Defcoin mainnet: dfcv/dfcp
    NetworkValues("DEFCOIN", "mainnet", "DFC", b'\x9e', b'\x1e', b'\5', h2b("02FA54D7"), h2b("02FA54AD")),

    # FAI faircoin mainnet : xprv/xpub
    NetworkValues(
        "Faircoin", "mainnet", "FAI", b'\xdf', b'\x5f', b'\x24', h2b("0488ADE4"), h2b("0488B21E")),

    # ARG argentum mainnet : xprv/xpub
    NetworkValues("Argentum", "mainnet", "ARG", b'\x97', b'\x17', b'\5', h2b("0488ADE4"), h2b("0488B21E")),

    # ZEC Zcash mainnet : xprv/xpub
    NetworkValues("Zcash", "mainnet", "ZEC", b'\x80', b'\x1C\xB8',
                  b'\x1C\xBD', h2b("0488ADE4"), h2b("0488B21E")),

    # BTCD BitcoinDark mainnet : xprv/xpub
    NetworkValues("BitcoinDark", "mainnet", "BTCD", b'\x44', b'\x3C', b'\55', h2b('0488ADE4'), h2b('0488B21E')),
)
