import binascii

class UnexpectedDER(Exception):
    pass

def encode_integer(r):
    assert r >= 0 # can't support negative numbers yet
    h = "%x" % r
    if len(h)%2:
        h = "0" + h
    s = binascii.unhexlify(h)
    if s[0] <= 0x7f:
        return b"\x02" + bytes([len(s)]) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b"\x02" + bytes([len(s)+1]) + b"\x00" + s

def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x30" + encode_length(total_len) + b"".join(encoded_pieces)

def remove_sequence(string):
    if not string.startswith(b"\x30"):
        raise UnexpectedDER("wanted sequence (0x30), got 0x%02x" %
                            string[0])
    length, lengthlength = read_length(string[1:])
    endseq = 1+lengthlength+length
    return string[1+lengthlength:endseq], string[endseq:]

def remove_integer(string):
    if not string.startswith(b"\x02"):
        raise UnexpectedDER("wanted integer (0x02), got 0x%02x" %
                            string[0])
    length, llen = read_length(string[1:])
    numberbytes = string[1+llen:1+llen+length]
    rest = string[1+llen+length:]
    assert numberbytes[0] < 0x80 # can't support negative numbers yet
    return int(binascii.hexlify(numberbytes), 16), rest

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return bytes([l])
    s = "%x" % l
    if len(s)%2:
        s = "0"+s
    s = binascii.unhexlify(s)
    llen = len(s)
    return bytes([0x80|llen]) + s

def read_length(string):
    if not (string[0] & 0x80):
        # short form
        return (string[0] & 0x7f), 1
    # else long-form: b0&0x7f is number of additional base256 length bytes,
    # big-endian
    llen = string[0] & 0x7f
    if llen > len(string)-1:
        raise UnexpectedDER("ran out of length bytes")
    return int(binascii.hexlify(string[1:1+llen]), 16), 1+llen
