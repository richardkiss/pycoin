#!/usr/bin/env python

from setuptools import setup

from pycoin.version import version

setup(
    name="pycoin",
    version=version,
    packages=[
        "pycoin",
        "pycoin.blockchain",
        "pycoin.cmds",
        "pycoin.coins",
        "pycoin.coins.bcash",
        "pycoin.coins.bgold",
        "pycoin.coins.bitcoin",
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
        "pycoin.tx",
        "pycoin.ui",
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
                # these scripts are obsolete
                'genwallet = pycoin.cmds.genwallet:main',
                'spend = pycoin.cmds.spend:main',
                'bu = pycoin.cmds.bitcoin_utils:main',
            ]
        },
    author_email="him@richardkiss.com",
    url="https://github.com/richardkiss/pycoin",
    license="http://opensource.org/licenses/MIT",
    description="Utilities for Bitcoin and altcoin addresses and transaction manipulation.",
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
