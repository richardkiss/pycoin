Getting Started with pycoin
===========================

Installation
------------
To install pycoin, run this command the terminal::

    $ pip install pycoin

If you don't have `pip <https://pip.pypa.io>`_ installed, check out
`this tutorial <http://docs.python-guide.org/en/latest/starting/installation/>`_.

To see if pycoin is correctly installed, try a command-line tool::

    $ ku 1

You should see several lines of output, describing information about the
bitcoin key corresponding to private key 1.


Networks
--------

A "network" is a particular coin, such as Bitcoin Mainnet or Bitcoin Testnet. There
are two main ways to fetch a network::

    from pycoin.symbols.btc import network
or ::

    from pycoin.networks.registry import network_for_netcode
    network = network_for_netcode("BTC")
