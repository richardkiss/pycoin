Multisig Recipes
================

These recipes include some command-line utilities written with many comments
and designed to be easy to follow. You can use them as a template for your own
code.


:mod:`1_create_address` Module
----------------------------------

This script shows you how to create a "2-of-3" multisig address. It requires BIP32 private key file.

.. automodule:: 1_create_address
    :members:
    :undoc-members:
    :show-inheritance:


:mod:`2_create_coinbase_tx` Module
----------------------------------

This script creates a fake coinbase transaction to an address of your choosing so you can test code that spends this output.

.. automodule:: 2_create_coinbase_tx
    :members:
    :undoc-members:
    :show-inheritance:


:mod:`3_create_unsigned_tx` Module
----------------------------------

This script shows you how to spend coins from an incoming transaction. It expects an incoming transaction in hex format a file ("incoming-tx.hex") and a bitcoin address, and it spends the coins from the selected output of in incoming transaction to the address you choose.

It does NOT sign the transaction. That's done by 4_sign_tx.py.

.. automodule:: 3_create_unsigned_tx
    :members:
    :undoc-members:
    :show-inheritance:


:mod:`4_sign_tx` Module
----------------------------------

.. automodule:: 4_sign_tx
    :members:
    :undoc-members:
    :show-inheritance: