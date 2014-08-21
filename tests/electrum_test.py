import unittest

from pycoin.key import Key
from pycoin.key.electrum import ElectrumWallet

MPK = 1
RECEIVING_ADDRESSES = [
    "1LDkC1H438qSnJLHCYkQ3WTZQkSEwoYGHc",
    "12mENAcc8ZhZbR6hv7LGm3jV7PwbYeF8Xk",
    "1A3NpABFd6YHvwr1ti1r8brU3BzQuV2Nr4",
    "1Gn6nWAoZrpmtV9zuNbyivWvRBpcygWaQX",
    "1M5i5P3DhtDbnvSTfmnUbcrTVgF8GDWQW9"
]
CHANGE_ADDRESSES = [
    "1iiAbyBTh1J69UzD1JcrfW8JSVJ9ve9gT",
    "146wnqmsQNYCZ6AXRCqLkzZyGM1ZU6nr3F",
    "1Mwexajvia3s8AcaGUkyEg9ZZJPJeTbKTZ"
]


class ElectrumTest(unittest.TestCase):
    def test_1(self):
        wallet = ElectrumWallet(initial_key="00000000000000000000000000000001")
        for idx, address in enumerate(RECEIVING_ADDRESSES):
            subkey = wallet.subkey("%s/0" % idx)
            calculated_address = subkey.address()
            self.assertEqual(address, calculated_address)
            wif = subkey.wif()
            key = Key.from_text(wif)
            self.assertEqual(key.address(use_uncompressed=True), address)
        for idx, address in enumerate(CHANGE_ADDRESSES):
            subkey = wallet.subkey("%s/1" % idx)
            calculated_address = subkey.address()
            self.assertEqual(address, calculated_address)
            wif = subkey.wif()
            key = Key.from_text(wif)
            self.assertEqual(key.address(use_uncompressed=True), address)
