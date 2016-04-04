from ..script import opcodes, tools
from ..script.check_signature import parse_signature_blob
from ..script.der import UnexpectedDER

from ... import ecdsa
from ... import encoding

from ...networks import address_prefix_for_netcode
from ...serialize import b2h

from ..exceptions import SolvingError

from .ScriptType import ScriptType, DEFAULT_PLACEHOLDER_SIGNATURE


# see BIP11 https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki

class ScriptMultisig(ScriptType):
    def __init__(self, n, sec_keys):
        self.n = n
        self.sec_keys = sec_keys
        self._script = None

    @classmethod
    def from_script(cls, script):
        pc = 0
        if len(script) == 0:
            raise ValueError("blank script")
        opcode, data, pc = tools.get_opcode(script, pc)

        if not opcodes.OP_1 <= opcode < opcodes.OP_16:
            raise ValueError("n value invalid")
        n = opcode + (1 - opcodes.OP_1)
        sec_keys = []
        while 1:
            if pc >= len(script):
                raise ValueError("unexpected end of script")
            opcode, data, pc = tools.get_opcode(script, pc)
            l = len(data) if data else 0
            if l < 33 or l > 120:
                break
            sec_keys.append(data)
        m = opcode + (1 - opcodes.OP_1)
        if n > m or len(sec_keys) != m:
            raise ValueError("m value wrong")

        opcode, data, pc = tools.get_opcode(script, pc)
        if opcode != opcodes.OP_CHECKMULTISIG:
            raise ValueError("no OP_CHECKMULTISIG")
        if pc != len(script):
            raise ValueError("extra stuff at end")

        return cls(sec_keys=sec_keys, n=n)

    def script(self):
        if self._script is None:
            # create the script
            # TEMPLATE = m {pubkey}...{pubkey} n OP_CHECKMULTISIG
            public_keys = [b2h(sk) for sk in self.sec_keys]
            script_source = "%d %s %d OP_CHECKMULTISIG" % (self.n, " ".join(public_keys), len(public_keys))
            self._script = tools.compile(script_source)
        return self._script

    def solve(self, **kwargs):
        """
        The kwargs required depend upon the script type.
        hash160_lookup:
            dict-like structure that returns a secret exponent for a hash160
        existing_script:
            existing solution to improve upon (optional)
        sign_value:
            the integer value to sign (derived from the transaction hash)
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

        sign_value = kwargs.get("sign_value")
        signature_type = kwargs.get("signature_type")

        signature_placeholder = kwargs.get("signature_placeholder", DEFAULT_PLACEHOLDER_SIGNATURE)

        secs_solved = set()
        existing_signatures = []
        existing_script = kwargs.get("existing_script")
        if existing_script:
            pc = 0
            seen = 0
            opcode, data, pc = tools.get_opcode(existing_script, pc)
            # ignore the first opcode
            while pc < len(existing_script) and seen < self.n:
                opcode, data, pc = tools.get_opcode(existing_script, pc)
                sig_pair, actual_signature_type = parse_signature_blob(data)
                seen += 1
                for sec_key in self.sec_keys:
                    try:
                        public_pair = encoding.sec_to_public_pair(sec_key)
                        sig_pair, signature_type = parse_signature_blob(data)
                        v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                        if v:
                            existing_signatures.append(data)
                            secs_solved.add(sec_key)
                            break
                    except (encoding.EncodingError, UnexpectedDER):
                        # if public_pair is invalid, we just ignore it
                        pass

        for signature_order, sec_key in enumerate(self.sec_keys):
            if sec_key in secs_solved:
                continue
            if len(existing_signatures) >= self.n:
                break
            hash160 = encoding.hash160(sec_key)
            result = db.get(hash160)
            if result is None:
                continue
            secret_exponent, public_pair, compressed = result
            binary_signature = self._create_script_signature(secret_exponent, sign_value, signature_type)
            existing_signatures.insert(signature_order, binary_signature)

        if signature_placeholder:
            while len(existing_signatures) < self.n:
                existing_signatures.append(signature_placeholder)

        script = "OP_0 %s" % " ".join(b2h(s) for s in existing_signatures)
        solution = tools.compile(script)
        return solution

    def info(self, netcode='BTC'):
        address_prefix = address_prefix_for_netcode(netcode)
        hash160s = [encoding.hash160(sk) for sk in self.sec_keys]
        addresses = [encoding.hash160_sec_to_bitcoin_address(h1, address_prefix=address_prefix)
                     for h1 in hash160s]
        return dict(type="multisig m of n", m=len(self.sec_keys), n=self.n, addresses=addresses,
                    hash160s=hash160s, script=self._script, address_prefix=address_prefix,
                    summary="%d of %s" % (self.n, addresses))

    def __repr__(self):
        info = self.info()
        return "<Script: multisig %d of %d (%s)>" % (info["n"], info["m"], "/".join(info["addresses"]))
