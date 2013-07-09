#!/usr/bin/env python

import distutils.core

version = "0.14"

distutils.core.setup(
    name="pycoin",
    version=version,
    packages = ["pycoin", "pycoin.ecdsa", "pycoin.tx", "pycoin.tx.script", "pycoin.serialize", "pycoin.scripts"],
    author="Richard Kiss",
    entry_points = { 'console_scripts': [ 'genwallet = pycoin.scripts.genwallet:main' ] },
    author_email="him@richardkiss.com",
    url="https://github.com/richardkiss/pycoin",
    license="http://opensource.org/licenses/MIT",
    description="A bunch of utilities that might be helpful when dealing with Bitcoin addresses and transactions."
)
