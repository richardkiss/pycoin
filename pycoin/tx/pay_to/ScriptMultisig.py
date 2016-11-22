from ..script import opcodes, tools
from ..script.check_signature import parse_signature_blob
from ..script.der import UnexpectedDER

from ... import ecdsa
from ... import encoding

from ...serialize import b2h

from ..exceptions import SolvingError

from .ScriptType import ScriptType, DEFAULT_PLACEHOLDER_SIGNATURE


# see BIP11 https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki

class ScriptMultisig(ScriptType):
    def __init__(self, m, sec_keys):
        self.m = m
        self.sec_keys = sec_keys
        self._script = None

    @classmethod
    def from_script(cls, script):
        pc = 0
        if len(script) == 0:
            raise ValueError("blank script")
        opcode, data, pc = tools.get_opcode(script, pc)

        if not opcodes.OP_1 <= opcode < opcodes.OP_16:
            raise ValueError("m value invalid")
        m = opcode + (1 - opcodes.OP_1)
        sec_keys = []
        while 1:
            if pc >= len(script):
                raise ValueError("unexpected end of script")
            opcode, data, pc = tools.get_opcode(script, pc)
            l = len(data) if data else 0
            if l < 33 or l > 120:
                break
            sec_keys.append(data)
        n = opcode + (1 - opcodes.OP_1)
        if m > n or len(sec_keys) != n:
            raise ValueError("n value wrong")

        opcode, data, pc = tools.get_opcode(script, pc)
        if opcode != opcodes.OP_CHECKMULTISIG:
            raise ValueError("no OP_CHECKMULTISIG")
        if pc != len(script):
            raise ValueError("extra stuff at end")

        return cls(sec_keys=sec_keys, m=m)

    def script(self):
        if self._script is None:
            # create the script
            # TEMPLATE = m {pubkey}...{pubkey} n OP_CHECKMULTISIG
            if len(self.sec_keys) < self.m:
                raise ValueError("m value invalid: Swap M and N (M of N) to match convention")

            public_keys = [b2h(sk) for sk in self.sec_keys]
            script_source = "%d %s %d OP_CHECKMULTISIG" % (self.m, " ".join(public_keys), len(public_keys))
            self._script = tools.compile(script_source)
        return self._script

    def _find_signatures(self, script, signature_for_hash_type_f, script_to_hash):
        signatures = []
        secs_solved = set()
        pc = 0
        seen = 0
        opcode, data, pc = tools.get_opcode(script, pc)
        # ignore the first opcode
        while pc < len(script) and seen < self.m:
            opcode, data, pc = tools.get_opcode(script, pc)
            try:
                sig_pair, signature_type = parse_signature_blob(data)
                seen += 1
                for idx, sec_key in enumerate(self.sec_keys):
                    public_pair = encoding.sec_to_public_pair(sec_key)
                    sign_value = signature_for_hash_type_f(signature_type, script_to_hash)
                    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                    if v:
                        signatures.append((idx, data))
                        secs_solved.add(sec_key)
                        break
            except (encoding.EncodingError, UnexpectedDER):
                # if public_pair is invalid, we just ignore it
                pass
        return signatures, secs_solved

    def solve(self, **kwargs):
        """
        The kwargs required depend upon the script type.
        hash160_lookup:
            dict-like structure that returns a secret exponent for a hash160
        existing_script:
            existing solution to improve upon (optional)
        signature_for_hash_type_f:
            function to return the sign value for a given signature hash
        signature_type:
            usually SIGHASH_ALL (1)
        signature_placeholder:
            The signature left in place when we don't have enough keys.
            Defaults to DEFAULT_PLACEHOLDER_SIGNATURE. Might want OP_0 instead.
        """
        # we need a hash160 => secret_exponent lookup
        db = kwargs.get("hash160_lookup")
        if db is None:
            raise SolvingError("missing hash160_lookup parameter")

        signature_for_hash_type_f = kwargs.get("signature_for_hash_type_f")
        signature_type = kwargs.get("signature_type")
        script_to_hash = kwargs.get("script_to_hash")

        signature_placeholder = kwargs.get("signature_placeholder", DEFAULT_PLACEHOLDER_SIGNATURE)

        secs_solved = set()
        existing_signatures = []
        existing_script = kwargs.get("existing_script")
        if existing_script:
            existing_signatures, secs_solved = self._find_signatures(
                existing_script, signature_for_hash_type_f, script_to_hash)

        for signature_order, sec_key in enumerate(self.sec_keys):
            if sec_key in secs_solved:
                continue
            if len(existing_signatures) >= self.m:
                break
            hash160 = encoding.hash160(sec_key)
            result = db.get(hash160)
            if result is None:
                continue
            secret_exponent, public_pair, compressed = result
            binary_signature = self._create_script_signature(
                secret_exponent, signature_for_hash_type_f, signature_type, script_to_hash)
            existing_signatures.append((signature_order, binary_signature))

        # make sure the existing signatures are in the right order
        existing_signatures.sort()

        # pad with placeholder signatures
        if signature_placeholder:
            while len(existing_signatures) < self.m:
                existing_signatures.append((-1, signature_placeholder))

        script = "OP_0 %s" % " ".join(b2h(s[1]) for s in existing_signatures)
        solution = tools.compile(script)
        return solution

    def hash160s(self):
        return [encoding.hash160(sec_key) for sec_key in self.sec_keys]

    def addresses_f(self, netcode=None):
        from pycoin.networks import address_prefix_for_netcode
        from pycoin.networks.default import get_current_netcode
        if netcode is None:
            netcode = get_current_netcode()
        address_prefix = address_prefix_for_netcode(netcode)
        addresses = [encoding.hash160_sec_to_bitcoin_address(h1, address_prefix=address_prefix)
                     for h1 in self.hash160s()]
        return addresses

    def info(self, netcode=None):
        return dict(type="multisig m of n", n=len(self.sec_keys), m=self.m, addresses_f=self.addresses_f,
                    hash160s=self.hash160s(), script=self._script)

    def __repr__(self):
        info = self.info()
        return "<Script: multisig %d of %d (%s)>" % (info["m"], info["n"], "/".join(self.addresses_f()))
