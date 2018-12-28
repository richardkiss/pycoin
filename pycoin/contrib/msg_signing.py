import io
import re

from binascii import b2a_base64, a2b_base64

from pycoin.intbytes import byte2int, int2byte
from pycoin.satoshi.satoshi_string import stream_satoshi_string

from ..encoding.bytes32 import to_bytes_32, from_bytes_32
from ..encoding.exceptions import EncodingError
from ..encoding.hash import double_sha256
from ..encoding.sec import public_pair_to_hash160_sec


class MessageSigner(object):

    # According to brainwallet, this is "inputs.io" format, but it seems practical
    # and is deployed in the wild. Core bitcoin doesn't offer a message wrapper like this.
    signature_template = ('-----BEGIN {net_name} SIGNED MESSAGE-----\n{msg}\n-----BEGIN '
                          'SIGNATURE-----\n{addr}\n{sig}\n-----END {net_name} SIGNED MESSAGE-----')

    def __init__(self, network, generator):
        self._network = network
        self._network_name = network.network_name
        self._generator = generator

    @classmethod
    def parse_sections(class_, msg_in):
        # Convert to Unix line feeds from DOS style, iff we find them, but
        # restore to same at the end. The RFC implies we should be using
        # DOS \r\n in the message, but that does not always happen in today's
        # world of MacOS and Linux devs. A mix of types will not work here.
        dos_nl = ('\r\n' in msg_in)
        if dos_nl:
            msg_in = msg_in.replace('\r\n', '\n')

        try:
            # trim any junk in front
            _, body = msg_in.split('SIGNED MESSAGE-----\n', 1)
        except ValueError:
            raise EncodingError("expecting text SIGNED MESSSAGE somewhere")

        # - sometimes middle sep is BEGIN BITCOIN SIGNATURE, other times just BEGIN SIGNATURE
        # - choose the last instance, in case someone signs a signed message
        parts = re.split('\n-----BEGIN [A-Z ]*SIGNATURE-----\n', body)
        if len(parts) < 2:
            raise EncodingError("expected BEGIN SIGNATURE line", body)
        msg, hdr = ''.join(parts[:-1]), parts[-1]

        if dos_nl:
            msg = msg.replace('\n', '\r\n')

        return msg, hdr

    @classmethod
    def parse_signed_message(class_, msg_in):
        """
        Take an "armoured" message and split into the message body, signing address
        and the base64 signature. Should work on all altcoin networks, and should
        accept both Inputs.IO and Multibit formats but not Armory.

        Looks like RFC2550 <https://www.ietf.org/rfc/rfc2440.txt> was an "inspiration"
        for this, so in case of confusion it's a reference, but I've never found
        a real spec for this. Should be a BIP really.
        """

        msg, hdr = class_.parse_sections(msg_in)

        # after message, expect something like an email/http headers, so split into lines
        hdr = list(filter(None, [i.strip() for i in hdr.split('\n')]))

        if '-----END' not in hdr[-1]:
            raise EncodingError("expecting END on last line")

        sig = hdr[-2]
        addr = None
        for line in hdr:
            line = line.strip()
            if not line:
                continue

            if line.startswith('-----END'):
                break

            if ':' in line:
                label, value = [i.strip() for i in line.split(':', 1)]

                if label.lower() == 'address':
                    addr = line.split(':')[1].strip()
                    break

                continue

            addr = line
            break

        if not addr or addr == sig:
            raise EncodingError("Could not find address")

        return msg, addr, sig

    def signature_for_message_hash(self, secret_exponent, msg_hash, is_compressed):
        """
        Return a signature, encoded in Base64, of msg_hash.
        """
        r, s, recid = self._generator.sign_with_recid(secret_exponent, msg_hash)

        # See http://bitcoin.stackexchange.com/questions/14263 and key.cpp
        # for discussion of the proprietary format used for the signature

        first = 27 + recid + (4 if is_compressed else 0)
        sig = b2a_base64(int2byte(first) + to_bytes_32(r) + to_bytes_32(s)).strip()
        sig = sig.decode("utf8")
        return sig

    def sign_message(self, key, message, verbose=False):
        """
        Return a signature, encoded in Base64, which can be verified by anyone using the
        public key.
        """
        secret_exponent = key.secret_exponent()
        if not secret_exponent:
            raise ValueError("Private key is required to sign a message")

        addr = key.address()

        msg_hash = self.hash_for_signing(message)
        is_compressed = key.is_compressed()

        sig = self.signature_for_message_hash(secret_exponent, msg_hash, is_compressed)

        if not verbose or message is None:
            return sig

        return self.signature_template.format(
            msg=message, sig=sig, addr=addr,
            net_name=self._network_name.upper())

    def pair_for_message_hash(self, signature, msg_hash):
        """
        Take a signature, encoded in Base64, and return the pair it was signed by.
        May raise EncodingError (from _decode_signature)
        """

        # Decode base64 and a bitmask in first byte.
        is_compressed, recid, r, s = self._decode_signature(signature)

        # Calculate the specific public key used to sign this message.
        y_parity = recid & 1
        q = self._generator.possible_public_pairs_for_signature(msg_hash, (r, s), y_parity=y_parity)[0]
        if recid > 1:
            order = self._generator.order()
            q = self._generator.Point(q[0] + order, q[1])
        return q, is_compressed

    def pair_matches_key(self, pair, key, is_compressed):
        # Check signing public pair is the one expected for the signature. It must be an
        # exact match for this key's public pair... or else we are looking at a validly
        # signed message, but signed by some other key.
        #
        if hasattr(key, "public_pair"):
            # expect an exact match for public pair.
            return key.public_pair() == pair
        else:
            # Key() constructed from a hash of pubkey doesn't know the exact public pair, so
            # must compare hashed addresses instead.
            key_hash160 = key.hash160()
            pair_hash160 = public_pair_to_hash160_sec(pair, compressed=is_compressed)
            return key_hash160 == pair_hash160

    def verify_message(self, key_or_address, signature, message=None, msg_hash=None):
        """
        Take a signature, encoded in Base64, and verify it against a
        key object (which implies the public key),
        or a specific base58-encoded pubkey hash.
        """
        if isinstance(key_or_address, str):
            # they gave us a private key or a public key already loaded.
            key = self._network.parse.address(key_or_address)
        else:
            key = key_or_address

        try:
            msg_hash = self.hash_for_signing(message) if message is not None else msg_hash
            pair, is_compressed = self.pair_for_message_hash(signature, msg_hash)
        except EncodingError:
            return False
        return self.pair_matches_key(pair, key, is_compressed)

    def msg_magic_for_netcode(self):
        """
        We need the constant "strMessageMagic" in C++ source code, from file "main.cpp"

        It is not shown as part of the signed message, but it is prefixed to the message
        as part of calculating the hash of the message (for signature). It's also what
        prevents a message signature from ever being a valid signature for a transaction.

        Each altcoin finds and changes this string... But just simple substitution.
        """
        return '%s Signed Message:\n' % self._network_name

    def _decode_signature(self, signature):
        """
            Decode the internal fields of the base64-encoded signature.
        """

        sig = a2b_base64(signature)
        if len(sig) != 65:
            raise EncodingError("Wrong length, expected 65")

        # split into the parts.
        first = byte2int(sig)
        r = from_bytes_32(sig[1:33])
        s = from_bytes_32(sig[33:33+32])

        # first byte encodes a bits we need to know about the point used in signature
        if not (27 <= first < 35):
            raise EncodingError("First byte out of range")

        # NOTE: The first byte encodes the "recovery id", or "recid" which is a 3-bit values
        # which selects compressed/not-compressed and one of 4 possible public pairs.
        #
        first -= 27
        is_compressed = bool(first & 0x4)

        return is_compressed, (first & 0x3), r, s

    def hash_for_signing(self, msg):
        """
        Return a hash of msg, according to odd bitcoin method: double SHA256 over a bitcoin
        encoded stream of two strings: a fixed magic prefix and the actual message.
        """
        magic = self.msg_magic_for_netcode()

        fd = io.BytesIO()
        stream_satoshi_string(fd, magic.encode('utf8'))
        stream_satoshi_string(fd, msg.encode('utf8'))

        # return as a number, since it's an input to signing algos like that anyway
        return from_bytes_32(double_sha256(fd.getvalue()))
