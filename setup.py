#!/usr/bin/env python

from setuptools import setup

version = "0.25"

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
            ]
        },
    author_email="him@richardkiss.com",
    url="https://github.com/richardkiss/pycoin",
    license="http://opensource.org/licenses/MIT",
    description="A bunch of utilities that might be helpful when dealing with Bitcoin addresses and transactions."
)
