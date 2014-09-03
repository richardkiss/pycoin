import io, os, hashlib, hmac
from binascii import b2a_base64, a2b_base64
from pycoin import ecdsa
from pycoin.ecdsa import ellipticcurve, intbytes, numbertheory

from pycoin.networks import address_prefix_for_netcode, network_name_for_netcode
from pycoin.encoding import public_pair_to_bitcoin_address, to_bytes_32, from_bytes_32, double_sha256

from .bip32 import Wallet

from pycoin.serialize.bitcoin_streamer import stream_bc_string

# According to brainwallet, this is "inputs.io" format, but it seems practical
# and is deployed in the wild. Core bitcoin doesn't offer a message wrapper like this.
signature_template = '''\
-----BEGIN {net_name} SIGNED MESSAGE-----
{msg}
-----BEGIN SIGNATURE-----
{addr}
{sig}
-----END {net_name} SIGNED MESSAGE-----'''

class MsgSigningMixin(object):
    # Use this with Key object, only? Needs lots of

    def sign_message(self, msg, verbose=False, use_uncompressed=None):
        """
        Return a signature, encoded in Base64, which can be verified by anyone using the
        public key.
        """
        secret_exponent = self.secret_exponent()
        if not secret_exponent:
            raise TypeError("Private key is required to sign a message")

        mhash = _hash_for_signing(msg, self.netcode)
        
        # Use a deterministic K so our signatures are deterministic.
        try:
            r, s, y_odd = _my_sign(ecdsa.generator_secp256k1, secret_exponent, mhash)
        except RuntimeError:
            # .. except if extremely unlucky
            k = from_bytes_32(os.urandom(32))
            r, s, y_odd = _my_sign(ecdsa.generator_secp256k1, secret_exponent, mhash, _k=k)

        is_compressed = not self._use_uncompressed(use_uncompressed)
        assert y_odd in (0, 1)

        # See http://bitcoin.stackexchange.com/questions/14263
        # for discussion of the proprietary format used for the signature
        #
        # Also from key.cpp:
        #
        # The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        #                  0x1D = second key with even y, 0x1E = second key with odd y,
        #                  add 0x04 for compressed keys.

        first = 27 + y_odd + (4 if is_compressed else 0)
        sig = b2a_base64(chr(first) + to_bytes_32(r) + to_bytes_32(s)).strip()

        if not verbose:
            return sig

        addr = self.address()

        return signature_template.format(msg=msg, sig=sig, addr=addr,
                            net_name=network_name_for_netcode(self.netcode).upper())
    


    def verify_message(self, msg, signature):
        """
        Take a signature, encoded in Base64, and verify it against ourself as a public key.
        """
        try:
            is_compressed, recid, r, s, mhash = decode_signature(msg, signature, self.netcode)
        except ValueError:
            return False

        # Calculate the specific public key used to sign this message.
        pair = extract_public_pair(ecdsa.generator_secp256k1, recid, r, s, mhash)

        # Check signing public pair is the one expected for the signature. It must be an
        # exact match for this key's public pair... or else we are looking at a validly
        # signed message, but signed by some other key
        pp = self.public_pair()
        if pp:
            # expect an exact match for public pair.
            return pp == pair
        else:
            # Key() constructed from a hash of pubkey doesn't know the exact public pair, so
            # must compare hashed addresses instead.
            addr = self.address()
            prefix = address_prefix_for_netcode(self.netcode)
            ta = public_pair_to_bitcoin_address(pair, compressed=is_compressed, address_prefix=prefix) 
            return ta == addr
            

def msg_magic_for_netcode(netcode):
    """
    We need the constant "strMessageMagic" in C++ source code, from file "main.cpp"
    
    Each altcoin finds and changes this string... But just simple substitution.
    """
    name = network_name_for_netcode(netcode)

    if netcode in ('BLK', 'BC'):
        name = "BlackCoin"     # Note: need this particular HumpCase

    return '%s Signed Message:\n' % name


def decode_signature(msg, signature, netcode='BTC'):
    """
    Decode the fields of the base64-encoded signature.
    """

    if signature[0] not in ('G', 'H', 'I'):
        # Because we know the first char is in range(27, 35), we know
        # valid first character is in this set.
        raise TypeError("Expected base64 value as signature", signature)

    # base 64 decode
    sig = a2b_base64(signature)
    if len(sig) != 65:
        raise ValueError("Wrong length, expected 65")

    # split into the parts.
    first = ord(sig[0])
    r = from_bytes_32(sig[1:33])
    s = from_bytes_32(sig[33:33+32])

    # first byte encodes a bits we need to know about the point used in signature
    if not (27 <= first < 35):
        raise ValueError("First byte out of range")

    # NOTE: we aren't using the number in the first byte because our
    # escda code doesn't allow us to put in the Y even/odd thing. Unfortunately
    # I think that means this code will accept some signatures that bitcoind would not,
    # but I don't see how you could generate those signatures, or what the use of that
    # could possibly be...
    #
    first -= 27
    is_compressed = bool(first & 0x4)

    mhash = _hash_for_signing(msg, netcode)
    return is_compressed, (first&0x3), r, s, mhash

def extract_public_pair(generator, recid, r, s, value):
    """
    Using the already-decoded parameters of the bitcoin signature, 
    return the specific public key pair used to sign this message.
    Caller must verify this pubkey is what was expected.
    """
    assert 0 <= recid < 4, recid

    G = generator
    n = G.order()

    # Check order of data; but okay because of way it's encoded, and this assert
    # is hella slow to evaluate.
    #assert 1 <= r < n
    #assert 1 <= s < n

    curve = G.curve()
    order = G.order()
    p = curve.p()

    x = r + (n * (recid / 2))

    alpha = ( pow(x,3,p)  + curve.a() * x + curve.b() ) % p
    beta = numbertheory.modular_sqrt(alpha, p)
    inv_r = numbertheory.inverse_mod(r,order)

    y = beta if ((beta - recid) % 2 == 0) else (p - beta)

    minus_e = -value % order

    R = ellipticcurve.Point(curve, x, y, order)
    Q = inv_r * ( s * R + minus_e * G )
    public_pair = (Q.x(), Q.y())

    # check that Q is the RIGHT public key? No. Leave that for the caller.

    return public_pair

def keys_from_signature(msg, signature, netcode='BTC'):
    """
    Decode the possible public keys corresponding to the 
    signature or raise if any problem. Returns a tuple: (is_compressed, pairs)
    The "pairs" are public-key pairs that could have signed the message (max 4).

    This is an exported function because it's useful by itself. If you had a signed
    message, but weren't sure of the public key used to generate it.
    """

    if signature[0] not in ('G', 'H', 'I'):
        # Because we know the first char is in range(27, 35), we know
        # valid first character is in this set.
        raise TypeError("Expected base64 value as signature", signature)

    # base 64 decode
    sig = a2b_base64(signature)
    if len(sig) != 65:
        raise ValueError("Wrong length, expected 65")

    # split into the parts.
    first = ord(sig[0])
    r = from_bytes_32(sig[1:33])
    s = from_bytes_32(sig[33:33+32])

    # first byte encodes a bits we need to know about the point used in signature
    if not (27 <= first < 35):
        raise ValueError("First byte out of range")

    # NOTE: we aren't using the number in the first byte because our
    # escda code doesn't allow us to put in the Y even/odd thing. Unfortunately
    # I think that means this code will accept some signatures that bitcoind would not,
    # but I don't see how you could generate those signatures, or what the use of that
    # could possibly be...
    #
    first -= 27
    is_compressed = bool(first & 0x4)

    mhash = _hash_for_signing(msg, netcode)
    return is_compressed, \
            ecdsa.possible_public_pairs_for_signature(ecdsa.generator_secp256k1, mhash, (r,s))

def _hash_for_signing(msg, netcode='BTC'):
    # Return a hash of msg, according to bitcoin method: double SHA256 over a bitcoin
    # encoded stream of two strings: a fixed magic prefix and the actual message.
    magic = msg_magic_for_netcode(netcode)
    fd = io.BytesIO()

    stream_bc_string(fd, magic)
    stream_bc_string(fd, msg)
    
    # return as a number, since it's an input to signing algos like that anyway
    return from_bytes_32(double_sha256(fd.getvalue()))

def _my_deterministic_generate_k(generator_order, secret_exponent, val, hash_f=hashlib.sha256):
    """
    Generate K value according to https://tools.ietf.org/html/rfc6979
    """
    n = generator_order
    order_size = (n.bit_length() + 7) // 8
    hash_size = hash_f().digest_size
    v = b'\x01' * hash_size
    k = b'\x00' * hash_size
    priv = intbytes.to_bytes(secret_exponent, length=order_size)
    shift = 8 * hash_size - n.bit_length()
    if shift > 0:
        val >>= shift
    if val > n:
        val -= n
    h1 = intbytes.to_bytes(val, length=order_size)
    k = hmac.new(k, v + b'\x00' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()
    k = hmac.new(k, v + b'\x01' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()

    while 1:
        t = bytearray()

        while len(t) < order_size:
            v = hmac.new(k, v, hash_f).digest()
            t.extend(v)

        k1 = intbytes.from_bytes(bytes(t))

        k1 >>= (len(t)*8 - n.bit_length())
        if k1 >= 1 and k1 < n:
            return k1

        k = hmac.new(k, v + b'\x00', hash_f).digest()
        v = hmac.new(k, v, hash_f).digest()


def _my_sign(generator, secret_exponent, val, _k=None):
    """Return a signature for the provided hash (val), using the provided
    random nonce, _k or generate a deterministic K as needed.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """
    G = generator
    n = G.order()
    k = _k or _my_deterministic_generate_k(n, secret_exponent, val)
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError("amazingly unlucky random number r")
    s = ( numbertheory.inverse_mod( k, n ) * \
          ( val + ( secret_exponent * r ) % n ) ) % n
    if s == 0: raise RuntimeError("amazingly unlucky random number s")

    return (r, s, p1.y() % 2)



def testit():
    from pycoin.key import Key
    from pycoin.encoding import wif_to_tuple_of_secret_exponent_compressed
    from pycoin.encoding import pubkey_address_to_hash160_sec_with_prefix

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

        h160, pubpre = pubkey_address_to_hash160_sec_with_prefix(right_addr)
        vk2 = Key(hash160=h160)
        assert vk2.address() == right_addr

        for i in range(1, 30, 10):
            msg = 'test message %s' % ('A'*i)
            sig = k.sign_message(msg, verbose=1)
            print sig
            assert right_addr in sig

            sig2 = k.sign_message(msg, verbose=0)
            assert sig2 in sig, (sig, sig2)

            ok = vk.verify_message(msg, sig2)
            print "verifies: %s" % ("Ok" if ok else "WRONG")
            assert ok

            assert vk2.verify_message(msg, sig2)
