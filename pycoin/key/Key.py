from pycoin import ecdsa
from pycoin.networks import address_prefix_for_netcode,\
    netcode_and_type_for_data, wif_prefix_for_netcode, network_name_for_netcode

from pycoin.encoding import a2b_hashed_base58, secret_exponent_to_wif,\
    public_pair_to_sec, hash160,\
    hash160_sec_to_bitcoin_address, sec_to_public_pair,\
    is_sec_compressed, to_bytes_32, from_bytes_32, EncodingError

from .bip32 import Wallet

from binascii import b2a_base64, a2b_base64


class Key(object):
    def __init__(self, hierarchical_wallet=None, secret_exponent=None,
                 public_pair=None, hash160=None, prefer_uncompressed=None, is_compressed=True, netcode='BTC'):
        """
        hierarchical_wallet:
            a bip32 wallet
        secret_exponent:
            a long representing the secret exponent
        public_pair:
            a tuple of long integers on the ecdsa curve
        hash160:
            a hash160 value corresponding to a bitcoin address
        Include at most one of hierarchical_wallet, secret_exponent, public_pair or hash160.
        prefer_uncompressed, is_compressed (booleans) are optional.
        netcode:
            the code for the network (as defined in pycoin.networks)
        """
        if [hierarchical_wallet, secret_exponent, public_pair, hash160].count(None) != 3:
            raise ValueError("exactly one of hierarchical_wallet, secret_exponent, public_pair, hash160"
                             " must be passed.")
        if prefer_uncompressed is None:
            prefer_uncompressed = not is_compressed
        self._prefer_uncompressed = prefer_uncompressed
        self._hierarchical_wallet = hierarchical_wallet
        self._secret_exponent = secret_exponent
        self._public_pair = public_pair
        if hash160:
            if is_compressed:
                self._hash160_compressed = hash160
            else:
                self._hash160_uncompressed = hash160
        self._netcode = netcode
        self._calculate_all()

    @classmethod
    def from_text(class_, text, is_compressed=True):
        """
        This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

        The "is_compressed" parameter is ignored unless a public address is passed in.
        """

        data = a2b_hashed_base58(text)
        netcode, key_type = netcode_and_type_for_data(data)
        data = data[1:]

        if key_type in ("pub32", "prv32"):
            hw = Wallet.from_wallet_key(text)
            return Key(hierarchical_wallet=hw, netcode=netcode)

        if key_type == 'wif':
            is_compressed = (len(data) > 32)
            if is_compressed:
                data = data[:-1]
            return Key(
                secret_exponent=from_bytes_32(data),
                prefer_uncompressed=not is_compressed, netcode=netcode)
        if key_type == 'address':
            return Key(hash160=data, is_compressed=is_compressed, netcode=netcode)
        raise EncodingError("unknown text: %s" % text)

    @classmethod
    def from_sec(class_, sec):
        """
        Create a key from an sec bytestream (which is an encoding of a public pair).
        """
        public_pair = sec_to_public_pair(sec)
        return Key(public_pair=public_pair, prefer_uncompressed=not is_sec_compressed(sec))

    def public_copy(self):
        """
        Create a copy of this key with private key information removed.
        """
        if self._hierarchical_wallet:
            return Key(hierarchical_wallet=self._hierarchical_wallet.public_copy())
        if self.public_pair():
            return Key(public_pair=self.public_pair())
        return self

    def _calculate_all(self):
        for attr in "_secret_exponent _public_pair _wif_uncompressed _wif_compressed _sec_compressed" \
                " _sec_uncompressed _hash160_compressed _hash160_uncompressed _address_compressed" \
                " _address_uncompressed _netcode".split():
                setattr(self, attr, getattr(self, attr, None))

        if self._hierarchical_wallet:
            if self._hierarchical_wallet.is_private:
                self._secret_exponent = self._hierarchical_wallet.secret_exponent
            else:
                self._public_pair = self._hierarchical_wallet.public_pair
            self._netcode = self._hierarchical_wallet.netcode

        wif_prefix = wif_prefix_for_netcode(self._netcode)

        if self._secret_exponent:
            self._wif_uncompressed = secret_exponent_to_wif(
                self._secret_exponent, compressed=False, wif_prefix=wif_prefix)
            self._wif_compressed = secret_exponent_to_wif(
                self._secret_exponent, compressed=True, wif_prefix=wif_prefix)
            self._public_pair = ecdsa.public_pair_for_secret_exponent(
                ecdsa.generator_secp256k1, self._secret_exponent)

        if self._public_pair:
            self._sec_compressed = public_pair_to_sec(self._public_pair, compressed=True)
            self._sec_uncompressed = public_pair_to_sec(self._public_pair, compressed=False)
            self._hash160_compressed = hash160(self._sec_compressed)
            self._hash160_uncompressed = hash160(self._sec_uncompressed)

        address_prefix = address_prefix_for_netcode(self._netcode)

        if self._hash160_compressed:
            self._address_compressed = hash160_sec_to_bitcoin_address(
                self._hash160_compressed, address_prefix=address_prefix)

        if self._hash160_uncompressed:
            self._address_uncompressed = hash160_sec_to_bitcoin_address(
                self._hash160_uncompressed, address_prefix=address_prefix)

    def as_text(self):
        """
        Return a textual representation of this key.
        """
        if self._hierarchical_wallet:
            return self._hierarchical_wallet.wallet_key(as_private=self._hierarchical_wallet.is_private)
        if self._secret_exponent:
            return self.wif()
        return self.address()

    def hierarchical_wallet(self):
        return self._hierarchical_wallet

    def hwif(self, as_private=False):
        """
        Return a textual representation of the hiearachical wallet (reduced to public), or None.
        """
        if self._hierarchical_wallet:
            return self._hierarchical_wallet.wallet_key(as_private=as_private)
        return None

    def secret_exponent(self):
        """
        Return an integer representing the secret exponent (or None).
        """
        return self._secret_exponent

    def public_pair(self):
        """
        Return a pair of integers representing the public key (or None).
        """
        return self._public_pair

    def _use_uncompressed(self, use_uncompressed):
        if use_uncompressed:
            return use_uncompressed
        if use_uncompressed is None:
            return self._prefer_uncompressed
        return False

    def wif(self, use_uncompressed=None):
        """
        Return the WIF representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._wif_uncompressed
        return self._wif_compressed

    def sec(self, use_uncompressed=None):
        """
        Return the SEC representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._sec_uncompressed
        return self._sec_compressed

    def hash160(self, use_uncompressed=None):
        """
        Return the hash160 representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._hash160_uncompressed
        return self._hash160_compressed

    def address(self, use_uncompressed=None):
        """
        Return the public address representation of this key, if available.
        If use_uncompressed is not set, the preferred representation is returned.
        """
        if self._use_uncompressed(use_uncompressed):
            return self._address_uncompressed
        return self._address_compressed

    def subkey(self, path_to_subkey):
        """
        Return the Key corresponding to the hierarchical wallet's subkey (or None).
        """
        if self._hierarchical_wallet:
            return Key(hierarchical_wallet=self._hierarchical_wallet.subkey_for_path(path_to_subkey))

    def subkeys(self, path_to_subkeys):
        """
        Return an iterator yielding Keys corresponding to the
        hierarchical wallet's subkey path (or just this key).
        """
        if self._hierarchical_wallet:
            for subwallet in self._hierarchical_wallet.subkeys_for_path(path_to_subkeys):
                yield Key(hierarchical_wallet=subwallet)
        else:
            yield self

    def sign_message(self, msg, verbose=False, use_uncompressed=None):
        """
        Return a signature, encoded in Base64, which can be verified by anyone using the
        public key.
        """
        if not self._secret_exponent:
            raise TypeError("Private key is required to sign a message")

        mhash = hash_for_signing(msg, self._netcode)
        
        r, s, y_odd = my_sign(ecdsa.generator_secp256k1, self._secret_exponent, mhash)

        is_compressed = not self._use_uncompressed(use_uncompressed)
        assert y_odd in (0, 1)

        # see http://bitcoin.stackexchange.com/questions/14263
        # for discussion of the proprietary format used for the signature
        # also from key.cpp:
        #
        # The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        #                  0x1D = second key with even y, 0x1E = second key with odd y,
        #                  add 0x04 for compressed keys.

        first = 27 + y_odd + (4 if is_compressed else 0)
        sig = b2a_base64(chr(first) + to_bytes_32(r) + to_bytes_32(s)).strip()

        if not verbose:
            return sig

        addr = self.address(use_uncompressed)

        return self.signature_template.format(msg=msg, sig=sig, addr=addr,
                            net_name=network_name_for_netcode(self._netcode).upper())

    # According to brainwallet, this is "inputs.io" format, but it seems practical
    # and is deployed. Core bitcoin doesn't offer a message wrapper like this.
    signature_template = '''\
-----BEGIN {net_name} SIGNED MESSAGE-----
{msg}
-----BEGIN SIGNATURE-----
{addr}
{sig}
-----END {net_name} SIGNED MESSAGE-----'''
    

    @classmethod
    def keys_from_signature(cls, msg, signature, netcode='BTC'):
        """
        Decode the possible public keys corresponding to the 
        signature or raise if any problem. Returns a tuple: (is_compressed, pairs)
        The "pairs" are public-key pairs that could have signed the message (max 4).
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
        # but I don't see how you could generate those signatures.
        first -= 27
        if first >= 4:
            is_compressed = True
            first -= 4

        mhash = hash_for_signing(msg, netcode)
        return is_compressed, \
                ecdsa.possible_public_pairs_for_signature(ecdsa.generator_secp256k1, mhash, (r,s))

    def verify_message(self, msg, signature):
        """
        Take a signature, encoded in Base64, and verify it against ourself as a public key.

        # Check each public pair that signature might correspond to. One must be an
        # exact match for this key's public pair... or else we are looking at a validly
        # signed message, but signed by another key.
        """
        try:
            is_compressed, pairs = self.keys_from_signature(msg, signature, self._netcode)
        except ValueError:
            return False

        for pair in pairs:
            if pair == self._public_pair:
                return True

        return False
            

from pycoin.serialize.bitcoin_streamer import stream_bc_string
from pycoin.networks import msg_magic_for_netcode
import io
from pycoin.encoding import double_sha256

def hash_for_signing(msg, netcode='BTC'):
    # Return a hash of msg, according to bitcoin method: double SHA256 over a bitcoin
    # encoded stream of two strings: a fixed magic prefix and the actual message.
    magic = msg_magic_for_netcode(netcode)
    fd = io.BytesIO()

    stream_bc_string(fd, magic)
    stream_bc_string(fd, msg)
    
    # return as a number, since it's an input to signing algos like that anyway
    return from_bytes_32(double_sha256(fd.getvalue()))

import hashlib, hmac
from pycoin.ecdsa import ellipticcurve, intbytes, numbertheory
def my_deterministic_generate_k(generator_order, secret_exponent, val, hash_f=hashlib.sha256):
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


def my_sign(generator, secret_exponent, val, _k=None):
    """Return a signature for the provided hash (val), using the provided
    random nonce, _k or generate a deterministic K as needed.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """
    G = generator
    n = G.order()
    k = _k or my_deterministic_generate_k(n, secret_exponent, val)
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError("amazingly unlucky random number r")
    s = ( numbertheory.inverse_mod( k, n ) * \
          ( val + ( secret_exponent * r ) % n ) ) % n
    if s == 0: raise RuntimeError("amazingly unlucky random number s")

    return (r, s, p1.y() % 2)


# test vectors from https://raw.githubusercontent.com/nanotube/supybot-bitcoin-marketmonitor/master/GPG/local/bitcoinsig.py
#

def testit():
    from pycoin.encoding import wif_to_tuple_of_secret_exponent_compressed
    #se, comp = wif_to_tuple_of_secret_exponent_compressed('5JkuZ6GLsMWBKcDWa5QiD15Uj467phPR')
    # based on 'dea7715ddcf5aba27530d6a1393813fbdd09af3aeb5f4f1616f563833d07babb', compressed=True
    se, comp = wif_to_tuple_of_secret_exponent_compressed('L4gXBvYrXHo59HLeyem94D9yLpRkURCHmCwQtPuWW9m6o1X8p8sp')
    k = Key(secret_exponent = se, is_compressed=comp)
    assert k.address() == '1LsPb3D1o1Z7CzEt1kv5QVxErfqzXxaZXv'

    for i in range(3):
        msg = 'test message %s' % i
        sig = k.sign_message(msg, verbose=1, use_uncompressed=False)
        print sig

        sig2 = k.sign_message(msg, verbose=0, use_uncompressed=False)
        assert sig2 in sig, (sig, sig2)

        ok = k.verify_message(msg, sig2)
        print "verifies: %s" % ("Ok" if ok else "WRONG")
        assert ok
