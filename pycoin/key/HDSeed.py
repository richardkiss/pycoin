import hashlib
import hmac
import struct

from ..encoding.bytes32 import from_bytes_32
from ..encoding.sec import sec_to_public_pair
from .Key import Key


class HDSeed:
    def __init__(self, data):
        self.data = data

    @classmethod
    def deserialize(class_, data):
        parent_fingerprint, child_index = struct.unpack(">4sL", data[5:13])
        d = dict(chain_code=data[13:45], depth=ord(data[4:5]), parent_fingerprint=parent_fingerprint,
                 child_index=child_index)
        is_private = (data[45:46] == b'\0')
        if is_private:
            d["secret_exponent"] = from_bytes_32(data[46:])
        else:
            d["public_pair"] = sec_to_public_pair(data[45:], generator=class_._generator)
        return class_(**d)

    def __repr__(self):
        return "<HDSeed with hash %s>" % hashlib.sha256(self.data).hexdigest()[:8]
