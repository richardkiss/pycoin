import binascii
import ipaddress
import struct

from pycoin.serialize.bitcoin_streamer import parse_struct


IP4_HEADER = binascii.unhexlify("00000000000000000000FFFF")


class PeerAddress(object):
    def __init__(self, services, ip_int_or_str, port):
        ip_address = ipaddress.ip_address(ip_int_or_str)
        self.services = services
        self.ip_address = ip_address
        self.port = port

    def __repr__(self):
        return "%s/%d" % (self.ip_address, self.port)

    def host(self):
        return self.ip_address.exploded

    def stream(self, f):
        f.write(struct.pack("<Q", self.services))
        ip_bin = self.ip_address.packed
        if len(ip_bin) < 16:
            f.write(IP4_HEADER)
        f.write(ip_bin)
        f.write(struct.pack("!H", self.port))

    @classmethod
    def parse(self, f):
        services, ip_bin, port = parse_struct("Q@h", f)
        if ip_bin.startswith(IP4_HEADER):
            ip_bin = ip_bin[len(IP4_HEADER):]
        ip_int = int.from_bytes(ip_bin, byteorder="big")
        return self(services, ip_int, port)

    def __lt__(self, other):
        return self.ip_address.packed < other.ip_address.packed

    def __eq__(self, other):
        return self.services == other.services and \
            self.ip_address == other.ip_address and self.port == other.port
