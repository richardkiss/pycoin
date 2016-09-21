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
        "pycoin.contrib",
        "pycoin.convention",
        "pycoin.ecdsa",
        "pycoin.ecdsa.native",
        "pycoin.key",
        "pycoin.message",
        "pycoin.networks",
        "pycoin.serialize",
        "pycoin.services",
        "pycoin.tx",
        "pycoin.tx.pay_to",
        "pycoin.tx.script",
        "pycoin.wallet"
    ],
    author="Richard Kiss",
    entry_points={
        'console_scripts':
            [
                'block = pycoin.cmds.block:main',
                'ku = pycoin.cmds.ku:main',
                'tx = pycoin.cmds.tx:main',
                'cache_tx = pycoin.cmds.cache_tx:main',
                'fetch_unspent = pycoin.cmds.fetch_unspent:main',
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
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],)
