pycoin
======

Release v\ |version|. (:ref:`Installation <install>`)

.. image:: https://codecov.io/github/richardkiss/pycoin/coverage.svg?branch=master
    :target: https://codecov.io/github/richardkiss/pycoin

.. image:: https://img.shields.io/pypi/l/pycoin.svg
    :target: https://pypi.python.org/pypi/pycoin

.. image:: https://img.shields.io/pypi/pyversions/pycoin.svg
    :target: https://pypi.python.org/pypi/pycoin

.. image:: https://travis-ci.org/richardkiss/pycoin.svg?branch=master
    :target: https://travis-ci.org/richardkiss/pycoin

This documentation is a work-in-progress, and your contributions are welcome at
<https://github.com/richardkiss/pycoin>.

The pycoin library implements many of utilities useful when dealing with bitcoin and some bitcoin-like
alt-coins. It has been tested with Python 2.7, 3.6 and 3.7.


A Note about Naming
-------------------

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

Networks
--------

Although pycoin is primarily engineered for bitcoin, it supports various altcoins to
various degrees (and has the capability to support altcoins fully... contributions
welcome!).


Contents:

.. toctree::
   :maxdepth: 1

   install
   api
   cmdtools
   source/recipes
   bitcoin
   source/contract
   source/pycoin.ecdsa
   source/pycoin.services


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

