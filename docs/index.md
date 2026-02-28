# pycoin

[![codecov.io](https://codecov.io/github/richardkiss/pycoin/coverage.svg?branch=master)](https://codecov.io/github/richardkiss/pycoin)
[![PyPI License](https://img.shields.io/pypi/l/pycoin.svg)](https://pypi.python.org/pypi/pycoin)
[![PyPI Python versions](https://img.shields.io/pypi/pyversions/pycoin.svg)](https://pypi.python.org/pypi/pycoin)

This documentation is a work-in-progress, and your contributions are welcome at
<https://github.com/richardkiss/pycoin>.

The pycoin library implements many of the utilities useful when dealing with bitcoin and some bitcoin-like
alt-coins. It has been tested with Python 2.7, 3.6 and 3.7.


## A Note about Naming

Many of the names of data structures in bitcoin, like "script pubkey",
are derived from names that came from the original C++ source code
(known here as the "satoshi client"). Often times, it appears these
names were chosen out of expediency, and frequently they are overly
generic which makes it difficult to understand or remember
what they are for.

With the benefit of time and a lack of legacy users, pycoin has had
the luxury to come up with alternative names for many of these structures
that more clearly suggest their actual use. We will use the pycoin names
for these structures in this documentation, but will also make mention
of the "official" names used by the satoshi client.

## Networks

Although pycoin is primarily engineered for bitcoin, it supports various altcoins to
various degrees (and has the capability to support altcoins fully... contributions
welcome!).

## Contents

- [Installation](install.md)
- [API Reference](api.md)
- [Command-line Tools](cmdtools.md)
- [Recipes](source/recipes.md)
- [Bitcoin Primer](bitcoin.md)
- [Contract](source/contract.md)
- [ECDSA](source/pycoin.ecdsa.md)
- [Services](source/pycoin.services.md)
