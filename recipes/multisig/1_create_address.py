#!/usr/bin/env python

# This script shows you how to create a "2-of-3" multisig address.
# It requires BIP32 private key file.

import os
import sys

from pycoin.encoding.hexbytes import b2h
from pycoin.symbols.btc import network


def main():
    if len(sys.argv) != 2:
        print("usage: %s bip32_key_file" % sys.argv[0])
        sys.exit(-1)
    with open(sys.argv[1], "r") as f:
        hwif = f.readline().strip()

    # turn the bip32 text into a BIP32Node object
    BIP32_KEY = network.parse(hwif)

    # create three sec_keys (these are public keys, streamed using the SEC format)

    SEC_0 = BIP32_KEY.subkey_for_path("0/0/0").sec()
    SEC_1 = BIP32_KEY.subkey_for_path("0/1/0").sec()
    SEC_2 = BIP32_KEY.subkey_for_path("0/2/0").sec()

    public_key_sec_list = [SEC_0, SEC_1, SEC_2]

    # create the 2-of-3 multisig script
    # any 2 signatures can release the funds
    pay_to_multisig_script = network.contract.for_multisig(2, public_key_sec_list)

    # create a "2-of-3" multisig address_for_multisig
    the_address = network.address.for_p2s(pay_to_multisig_script)

    print("Here is your pay 2-of-3 address: %s" % the_address)

    print("Here is the pay 2-of-3 script: %s" % b2h(pay_to_multisig_script))
    print("The hex script should go into p2sh_lookup.hex")

    base_dir = os.path.abspath(os.path.dirname(sys.argv[1]))
    print("The three WIFs are written into %s as wif0, wif1 and wif2" % base_dir)
    for i in range(3):
        wif = BIP32_KEY.subkey_for_path("0/%d/0" % i).wif()
        with open(os.path.join(base_dir, "wif%d" % i), "w") as f:
            f.write(wif)


if __name__ == '__main__':
    main()
