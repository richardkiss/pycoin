# -*- coding: utf-8 -*-
"""
Deal with DER encoding and decoding.

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

import binascii

bytes_from_int = chr if bytes == str else lambda x: bytes([x])

class UnexpectedDER(Exception):
    pass

def encode_integer(r):
    assert r >= 0 # can't support negative numbers yet
    h = "%x" % r
    if len(h)%2:
        h = "0" + h
    s = binascii.unhexlify(h.encode("utf8"))
    if ord(s[:1]) <= 0x7f:
        return b"\x02" + bytes_from_int(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b"\x02" + bytes_from_int(len(s)+1) + b"\x00" + s

def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x30" + encode_length(total_len) + b"".join(encoded_pieces)

def remove_sequence(string):
    if not string.startswith(b"\x30"):
        raise UnexpectedDER("wanted sequence (0x30), got 0x%02x" %
                            ord(string[:1]))
    length, lengthlength = read_length(string[1:])
    endseq = 1+lengthlength+length
    return string[1+lengthlength:endseq], string[endseq:]

def remove_integer(string):
    if not string.startswith(b"\x02"):
        raise UnexpectedDER("wanted integer (0x02), got 0x%02x" %
                            ord(string[:1]))
    length, llen = read_length(string[1:])
    numberbytes = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    assert ord(numberbytes[:1]) < 0x80 # can't support negative numbers yet
    return int(binascii.hexlify(numberbytes), 16), rest

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return bytes_from_int(l)
    s = "%x" % l
    if len(s)%2:
        s = "0"+s
    s = binascii.unhexlify(s)
    llen = len(s)
    return bytes_from_int(0x80|llen) + s

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

def sigdecode_der(sig_der):
    rs_strings, empty = remove_sequence(sig_der)
    if empty != b"":
        raise UnexpectedDER("trailing junk after DER sig: %s" %
                                binascii.hexlify(empty))
    r, rest = remove_integer(rs_strings)
    s, empty = remove_integer(rest)
    if empty != b"":
        raise UnexpectedDER("trailing junk after DER numbers: %s" %
                                binascii.hexlify(empty))
    return r, s
