#!/usr/bin/env python
import unittest

def test_against_myself():
    """
    Test code that verifies against ourselves only. Useful but not so great.
    """
    from pycoin.key import Key
    from pycoin.encoding import bitcoin_address_to_hash160_sec_with_prefix
    from pycoin.encoding import wif_to_tuple_of_secret_exponent_compressed
    from pycoin.key.msg_signing import parse_signed_message

    for wif, right_addr in [
                    ('L4gXBvYrXHo59HLeyem94D9yLpRkURCHmCwQtPuWW9m6o1X8p8sp',
                            '1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv'),
                    ('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss',
                            '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'),
                ]:
        se, comp = wif_to_tuple_of_secret_exponent_compressed(wif)

        k = Key(secret_exponent=se, is_compressed=comp)
        assert k.address() == right_addr

        print "\nAddr %s compressed=%s" % (right_addr, comp)

        vk = Key(public_pair=k.public_pair(), is_compressed=comp)
        assert vk.address() == right_addr

        h160, pubpre = bitcoin_address_to_hash160_sec_with_prefix(right_addr)
        vk2 = Key(hash160=h160)
        assert vk2.address() == right_addr

        for i in range(1, 30, 10):
            msg = 'test message %s' % ('A'*i)
            sig = k.sign_message(msg, verbose=1)
            print sig
            assert right_addr in sig

            # check parsing works
            m,a,s = parse_signed_message(sig)
            assert m == msg, m
            assert a == right_addr, a

            sig2 = k.sign_message(msg, verbose=0)
            assert sig2 in sig, (sig, sig2)

            assert s == sig2, s

            ok = vk.verify_message(sig2, msg)
            print "verifies: %s" % ("Ok" if ok else "WRONG")
            assert ok

            assert vk2.verify_message(sig2, msg)

def test_msg_parse():
    """
    Test against real-world signatures found in the wild.
    """
    from pycoin.key.msg_signing import parse_signed_message, verify_message

    # Output from brainwallet in "multibit" mode.
    multibit = '''

-----BEGIN BITCOIN SIGNED MESSAGE-----
This is an example of a signed message.
-----BEGIN BITCOIN SIGNATURE-----
Version: Bitcoin-qt (1.0)
Address: 1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN

HCT1esk/TWlF/o9UNzLDANqsPXntkMErf7erIrjH5IBOZP98cNcmWmnW0GpSAi3wbr6CwpUAN4ctNn1T71UBwSc=
-----END BITCOIN SIGNATURE-----

'''
    m,a,s = parse_signed_message(multibit)
    assert m == 'This is an example of a signed message.'
    assert a == '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'
    assert s == \
        'HCT1esk/TWlF/o9UNzLDANqsPXntkMErf7erIrjH5IBOZP98cNcmWmnW0GpSAi3wbr6CwpUAN4ctNn1T71UBwSc='
    ok = verify_message(m, a, s, netcode='BTC')
    assert ok

    # Sampled from: https://www.bitrated.com/u/Bit2c.txt on Sep 3/2014
    bit2c = '''\
Username: Bit2c
Public key: 0396267072e597ad5d043db7c73e13af84a77a7212871f1aade607fb0f2f96e1a8
Public key address: 15etuU8kwLFCBbCNRsgQTvWgrGWY9829ej
URL: https://www.bitrated.com/u/Bit2c

-----BEGIN BITCOIN SIGNED MESSAGE-----
We will try to contact both parties to gather information and evidence, and do my best to make rightful judgement. Evidence may be submitted to us on https://www.bit2c.co.il/home/contact or in a private message to info@bit2c.co.il or in any agreed way.

https://www.bit2c.co.il
-----BEGIN SIGNATURE-----
15etuU8kwLFCBbCNRsgQTvWgrGWY9829ej
H2utKkquLbyEJamGwUfS9J0kKT4uuMTEr2WX2dPU9YImg4LeRpyjBelrqEqfM4QC8pJ+hVlQgZI5IPpLyRNxvK8=
-----END BITCOIN SIGNED MESSAGE-----
'''
    m,a,s = parse_signed_message(bit2c)
    assert a == '15etuU8kwLFCBbCNRsgQTvWgrGWY9829ej'
    assert s == 'H2utKkquLbyEJamGwUfS9J0kKT4uuMTEr2WX2dPU9YImg4LeRpyjBelrqEqfM4QC8pJ+hVlQgZI5IPpLyRNxvK8='
    ok = verify_message(m, a, s, netcode='BTC')
    assert ok

    # testnet example
    # Sampled from: http://testnet.bitrated.com/u/bearbin.txt on Sep 3/2014
    # NOTE: Testnet3
    bearbin = '''\
Username: bearbin
Public key: 03fc594c16779054fc5e119c309215c1f40f2ce104b0169cddeb6d20445bd28f67
Public key address: n2D9XsQX1mDpFGgYqsfmePTy61LJFQnXQM
URL: http://testnet.bitrated.com/u/bearbin

-----BEGIN BITCOIN SIGNED MESSAGE-----
Contact
-----------

bearbin@gmail.com - Email or hangouts (text only).

/u/bearbin on reddit (slow response, not preferred for use with the service, just for contact).

Resolution Guidelines:
-----------------------------

 * Evidence is needed. (e.g. pictures w/ proof that it's you).
 * If anybody fails to respond, money goes to the other person after 2 weeks.
 * Additional terms available on request.

Pricing
----------

 * 0.7% Min 0.003 Max 0.15
 * Payment in advance.
-----BEGIN SIGNATURE-----
n2D9XsQX1mDpFGgYqsfmePTy61LJFQnXQM
IEackZgifpBJs3SqQQ6leUwzvakTZgUKTDuCCn6rVMOQgHlIEzWSYZGQu2H+1chvu68uutzt04cGmsHy/kRIaEc=
-----END BITCOIN SIGNED MESSAGE-----
'''
    m,a,s = parse_signed_message(bearbin)
    assert a == 'n2D9XsQX1mDpFGgYqsfmePTy61LJFQnXQM'
    assert s == 'IEackZgifpBJs3SqQQ6leUwzvakTZgUKTDuCCn6rVMOQgHlIEzWSYZGQu2H+1chvu68uutzt04cGmsHy/kRIaEc='
    ok = verify_message(m, a, s, netcode='XTN')
    assert ok


def test_special_k():
    """
    Check that my reworked version of ecdsa.deterministic_generate_k works like the 
    old one, minus my salt
    """
    import random
    from pycoin.ecdsa.ecdsa import deterministic_generate_k
    from pycoin.ecdsa import generator_secp256k1

    from pycoin.key.msg_signing import deterministic_make_k

    order = generator_secp256k1.order()
    r = random.Random(42)
    saw = set()
    for i in range(10000):
        se = r.randint(2, order-2)
        val = r.randint(0, 2**32)

        old = deterministic_generate_k(order, se, val)
        new = deterministic_make_k(order, se, val, trust_no_one=False)

        assert old == new
        assert new not in saw
        saw.add(new)



class MsgSigningTests(unittest.TestCase):
    # Sigh. Would rather use py.test! and unittest.FunctionTestCase broke things for me.
    def test_1(self):
        test_against_myself()

    def test_2(self):
        test_msg_parse()

    def test_k(self):
        test_special_k()

if __name__ == "__main__":
    unittest.main()

# EOF
