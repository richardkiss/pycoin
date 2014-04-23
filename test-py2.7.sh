#!/bin/sh

python -m unittest pycoin.test.__init__
python -m unittest pycoin.test.build_tx_test
python -m unittest pycoin.test.ecdsa_test
python -m unittest pycoin.test.encoding_test
python -m unittest pycoin.test.key_translation_test
python -m unittest pycoin.test.parse_block_test
python -m unittest pycoin.test.signature_test
python -m unittest pycoin.test.validate_tx_test
python -m unittest pycoin.test.bip32_test
