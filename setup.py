#!/usr/bin/env python

from setuptools import setup

version = "0.26"

setup(
    name="pycoin",
    version=version,
    packages = [
        "pycoin",
        "pycoin.convention",
        "pycoin.ecdsa",
        "pycoin.tx",
        "pycoin.tx.script",
        "pycoin.serialize",
        "pycoin.services",
        "pycoin.scripts"
    ],
    author="Richard Kiss",
    entry_points = { 'console_scripts':
            [
                'genwallet = pycoin.scripts.genwallet:main',
                'spend = pycoin.scripts.spend:main',
                'bu = pycoin.scripts.bitcoin_utils:main',
                'fetch_unspent = pycoin.scripts.fetch_unspent:main',
                'create_tx = pycoin.scripts.create_tx:main',
                'dump_tx = pycoin.scripts.dump_tx:main',
                'fetch_tx = pycoin.scripts.fetch_tx:main',
                'sign_tx = pycoin.scripts.sign_tx:main',
                'simple_create_tx = pycoin.scripts.simple_create_tx:main',
                'simple_sign_tx = pycoin.scripts.simple_sign_tx:main',
            ]
        },
    author_email="him@richardkiss.com",
    url="https://github.com/richardkiss/pycoin",
    license="http://opensource.org/licenses/MIT",
    description="A bunch of utilities that might be helpful when dealing with Bitcoin addresses and transactions."
)
