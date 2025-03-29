#!/usr/bin/env python

from setuptools import setup

with open("README.md", "rt") as fh:
    long_description = fh.read()

setup(
    use_scm_version=True,
    name="pycoin",
    packages=[
        "pycoin",
        "pycoin.blockchain",
        "pycoin.cmds",
        "pycoin.coins",
        "pycoin.coins.bcash",
        "pycoin.coins.bgold",
        "pycoin.coins.bitcoin",
        "pycoin.coins.groestlcoin",
        "pycoin.coins.litecoin",
        "pycoin.contrib",
        "pycoin.convention",
        "pycoin.ecdsa",
        "pycoin.ecdsa.native",
        "pycoin.encoding",
        "pycoin.key",
        "pycoin.message",
        "pycoin.networks",
        "pycoin.satoshi",
        "pycoin.serialize",
        "pycoin.services",
        "pycoin.solve",
        "pycoin.symbols",
        "pycoin.vm",
        "pycoin.wallet",
    ],
    entry_points={
        "console_scripts": [
            "block = pycoin.cmds.block:main",
            "ku = pycoin.cmds.ku:main",
            "tx = pycoin.cmds.tx:main",
            "msg = pycoin.cmds.msg:main",
            "keychain = pycoin.cmds.keychain:main",
            "b58 = pycoin.cmds.b58:main",
            "coinc = pycoin.cmds.coinc:main",
        ]
    },
)
