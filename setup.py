#!/usr/bin/env python

from setuptools import setup

with open("README.md", "rt") as fh:
    long_description = fh.read()

setup(
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
        "pycoin.wallet"
    ],
    author="Richard Kiss",
    entry_points={
        'console_scripts':
            [
                'block = pycoin.cmds.block:main',
                'ku = pycoin.cmds.ku:main',
                'tx = pycoin.cmds.tx:main',
                'msg = pycoin.cmds.msg:main',
                'keychain = pycoin.cmds.keychain:main',
                'b58 = pycoin.cmds.b58:main',
                'coinc = pycoin.cmds.coinc:main',
            ]
        },
    author_email="him@richardkiss.com",
    url="https://github.com/richardkiss/pycoin",
    license="http://opensource.org/licenses/MIT",
    description="Utilities for Bitcoin and altcoin addresses and transaction manipulation.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],)
