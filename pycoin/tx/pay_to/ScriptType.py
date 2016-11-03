import collections

from pycoin import ecdsa

from ..script import der, opcodes, tools


bytes_from_int = chr if bytes == str else lambda x: bytes([x])


def generate_default_placeholder_signature():
    order = ecdsa.generator_secp256k1.order()
    r, s = order - 1, order // 2
    return der.sigencode_der(r, s) + bytes_from_int(1)


DEFAULT_PLACEHOLDER_SIGNATURE = generate_default_placeholder_signature()


class ScriptType(object):
    def __init__(self):
        raise NotImplemented()

    @classmethod
    def subclasses(cls, skip_self=True):
        for c in cls.__subclasses__():
            for c1 in c.subclasses(skip_self=False):
                yield c1
            if not skip_self:
                yield cls

    @classmethod
    def from_address(cls, text, netcodes=None):
        for sc in cls.subclasses():
            try:
                st = sc.from_address(text, netcodes=netcodes)
                return st
            except Exception:
                pass

    @classmethod
    def from_script(cls, script):
        for sc in cls.subclasses():
            try:
                st = sc.from_script(script)
                return st
            except Exception:
                pass

    @classmethod
    def match(cls, script):
        template = cls.TEMPLATE
        r = collections.defaultdict(list)
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script) and pc2 == len(template):
                return r
            if pc1 >= len(script) or pc2 >= len(template):
                break
            opcode1, data1, pc1 = tools.get_opcode(script, pc1)
            opcode2, data2, pc2 = tools.get_opcode(template, pc2)
            l1 = 0 if data1 is None else len(data1)
            if opcode2 == opcodes.OP_PUBKEY:
                if l1 < 33 or l1 > 120:
                    break
                r["PUBKEY_LIST"].append(data1)
            elif opcode2 == opcodes.OP_PUBKEYHASH:
                if l1 != 160/8:
                    break
                r["PUBKEYHASH_LIST"].append(data1)
            elif opcode2 == opcodes.OP_NULLDATA:
                r["NULLDATA_LIST"].append(data1)
            elif (opcode1, data1) != (opcode2, data2):
                break
        raise ValueError("script doesn't match")

    def _create_script_signature(
            self, secret_exponent, signature_for_hash_type_f, signature_type, script):
        sign_value = signature_for_hash_type_f(signature_type, script)
        order = ecdsa.generator_secp256k1.order()
        r, s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, sign_value)
        if s + s > order:
            s = order - s
        return der.sigencode_der(r, s) + bytes_from_int(signature_type)

    def address(self, netcode=None):
        from pycoin.networks.default import get_current_netcode
        if netcode is None:
            netcode = get_current_netcode()
        return self.info(netcode=netcode)["address_f"](netcode)

    def solve(self, **kwargs):
        """
        The kwargs required depend upon the script type.
        """
        raise NotImplemented()
