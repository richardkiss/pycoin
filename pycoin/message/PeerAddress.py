import functools
import struct

from pycoin.intbytes import iterbytes
from pycoin.satoshi.satoshi_struct import parse_struct
from pycoin.encoding.hexbytes import h2b


IP4_HEADER = h2b("00000000000000000000FFFF")


def ip_bin_to_ip6_addr(ip_bin):
    return ":".join("%x" % v for v in struct.unpack(">HHHHHHHH", ip_bin))


def ip_bin_to_ip4_addr(ip_bin):
    return "%d.%d.%d.%d" % tuple(iterbytes(ip_bin[-4:]))


@functools.total_ordering
class PeerAddress(object):
    def __init__(self, services, ip_bin, port):
        self.services = int(services)
        assert isinstance(ip_bin, bytes)
        if len(ip_bin) == 4:
            ip_bin = IP4_HEADER + ip_bin
        assert len(ip_bin) == 16
        self.ip_bin = ip_bin
        self.port = port

    def __repr__(self):
        return "%s/%d" % (self.host(), self.port)

    def host(self):
        if self.ip_bin.startswith(IP4_HEADER):
            return ip_bin_to_ip4_addr(self.ip_bin[-4:])
        return ip_bin_to_ip6_addr(self.ip_bin)

    def stream(self, f):
        f.write(struct.pack("<Q", self.services))
        f.write(self.ip_bin)
        f.write(struct.pack("!H", self.port))

    @classmethod
    def parse(self, f):
        services, ip_bin, port = parse_struct("Q@h", f)
        self.ip_bin = ip_bin
        return self(services, self.ip_bin, port)

    def __lt__(self, other):
        return (self.ip_bin, self.port, self.services) < (other.ip_bin, other.port, other.services)

    def __eq__(self, other):
        return self.services == other.services and \
            self.ip_bin == other.ip_bin and self.port == other.port
