import binascii
from pycoin.intbytes import int2byte


class UnexpectedDER(Exception):
    pass


def encode_integer(r):
    assert r >= 0  # can't support negative numbers yet
    h = "%x" % r
    if len(h) % 2:
        h = "0" + h
    s = binascii.unhexlify(h.encode("utf8"))
    if ord(s[:1]) <= 0x7f:
        return b"\x02" + int2byte(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b"\x02" + int2byte(len(s)+1) + b"\x00" + s


def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x30" + encode_length(total_len) + b"".join(encoded_pieces)


def remove_sequence(string):
    if not string.startswith(b"\x30"):
        raise UnexpectedDER(
            "wanted sequence (0x30), got string length %d %s" % (
                len(string), binascii.hexlify(string[:10])))
    length, lengthlength = read_length(string[1:])
    endseq = 1+lengthlength+length
    return string[1+lengthlength:endseq], string[endseq:]


def remove_integer(string, use_broken_open_ssl_mechanism=False):
    # OpenSSL treats DER-encoded negative integers (that have their most significant
    # bit set) as positive integers. Some apps depend upon this bug.
    if not string.startswith(b"\x02"):
        raise UnexpectedDER("did not get expected integer 0x02")
    length, llen = read_length(string[1:])
    if len(string) < 1+llen+length:
        raise UnexpectedDER("ran out of integer bytes")
    numberbytes = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    v = int(binascii.hexlify(numberbytes), 16)
    if ord(numberbytes[:1]) >= 0x80:
        if not use_broken_open_ssl_mechanism:
            v -= (1 << (8 * length))
    return v, rest


def encode_length(length):
    assert length >= 0
    if length < 0x80:
        return int2byte(length)
    s = "%x" % length
    if len(s) % 2:
        s = "0"+s
    s = binascii.unhexlify(s)
    llen = len(s)
    return int2byte(0x80 | llen) + s


def read_length(string):
    s0 = ord(string[:1])
    if not (s0 & 0x80):
        # short form
        return (s0 & 0x7f), 1
    # else long-form: b0&0x7f is number of additional base256 length bytes,
    # big-endian
    llen = s0 & 0x7f
    if llen > len(string)-1:
        raise UnexpectedDER("ran out of length bytes")
    return int(binascii.hexlify(string[1:1+llen]), 16), 1+llen


def sigencode_der(r, s):
    return encode_sequence(encode_integer(r), encode_integer(s))


def sigdecode_der(sig_der, use_broken_open_ssl_mechanism=True):
    # if use_broken_open_ssl_mechanism is true, this is a non-standard implementation
    rs_strings, empty = remove_sequence(sig_der)
    r, rest = remove_integer(rs_strings, use_broken_open_ssl_mechanism=use_broken_open_ssl_mechanism)
    s, empty = remove_integer(rest, use_broken_open_ssl_mechanism=use_broken_open_ssl_mechanism)
    return r, s


"""
Adapted from python-ecdsa at https://github.com/warner/python-ecdsa
Copyright (c) 2010 Brian Warner
Portions written in 2005 by Peter Pearson and placed in the public domain.


The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
