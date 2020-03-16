# generic solver

import pdb

from pycoin.coins.SolutionChecker import ScriptError
from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.encoding.exceptions import EncodingError
from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h
from pycoin.encoding.sec import public_pair_to_sec, sec_to_public_pair
from pycoin.intbytes import indexbytes, int2byte
from pycoin.satoshi import der

from .constraints import Atom
from .ConstraintSolver import CONSTANT, VAR, LIST, SolvingError


DEFAULT_PLACEHOLDER_SIGNATURE = b''
DEFAULT_SIGNATURE_TYPE = 1


def _find_signatures(script_blobs, generator_for_signature_type_f, signature_for_hash_type_f, max_sigs, sec_keys):
    signatures = []
    secs_solved = set()
    seen = 0
    for data in script_blobs:
        if seen >= max_sigs:
            break
        try:
            sig_pair, signature_type = parse_signature_blob(data)
            generator = generator_for_signature_type_f(signature_type)
            seen += 1
            for idx, sec_key in enumerate(sec_keys):
                public_pair = sec_to_public_pair(sec_key, generator)
                sign_value = signature_for_hash_type_f(signature_type)
                v = generator.verify(public_pair, sign_value, sig_pair)
                if v:
                    signatures.append((idx, data))
                    secs_solved.add(sec_key)
                    break
        except (ValueError, EncodingError, der.UnexpectedDER, ScriptError):
            # if public_pair is invalid, we just ignore it
            pass
    return signatures, secs_solved


def hash_lookup_solver(m):

    def f(solved_values, **kwargs):
        the_hash = m["the_hash"]
        db = kwargs.get("hash160_lookup", {})
        result = db.get(the_hash)
        if result is None:
            result = kwargs.get("sec_hints", {}).get(the_hash)
            if result:
                return {m["1"]: result}
        if result is None:
            raise SolvingError("can't find public pair for %s" % b2h(the_hash))
        sec = public_pair_to_sec(result[1], compressed=result[2])
        return {m["1"]: sec}

    return (f, [m["1"]], ())


hash_lookup_solver.pattern = ('EQUAL', CONSTANT("the_hash"), ('HASH160', VAR("1")))


def constant_equality_solver(m):

    def f(solved_values, **kwargs):
        return {m["var"]: m["const"]}

    return (f, [m["var"]], ())


constant_equality_solver.pattern = ('EQUAL', VAR("var"), CONSTANT('const'))


def all_signature_hints(public_pair, signature_for_hash_type_f, **kwargs):
    default_sig_type = [kwargs.get("signature_type", DEFAULT_SIGNATURE_TYPE)]
    sig_hash_types_to_try = kwargs.get("sig_hash_types_to_try", default_sig_type)
    shfsh = kwargs.get("signature_hints_for_sig_hash")
    if shfsh:
        for sig_hash_type in sig_hash_types_to_try:
            sig_hash = signature_for_hash_type_f(sig_hash_type)
            for _ in shfsh.get(sig_hash, []):
                yield _
    shfpp = kwargs.get("signature_hints_for_public_pair")
    if shfpp:
        for _ in shfpp.get(public_pair, []):
            yield _
    for _ in kwargs.get("signature_hints", []):
        yield _


def signing_solver(m):
    def f(solved_values, **kwargs):
        signature_type = kwargs.get("signature_type", DEFAULT_SIGNATURE_TYPE)
        generator_for_signature_type_f = kwargs["generator_for_signature_type_f"]
        signature_for_hash_type_f = m["signature_for_hash_type_f"]
        existing_script = kwargs.get("existing_script", b'')
        existing_signatures, secs_solved = _find_signatures(
            existing_script, generator_for_signature_type_f, signature_for_hash_type_f,
            len(m["sig_list"]), m["sec_list"])

        sec_keys = m["sec_list"]
        signature_variables = m["sig_list"]

        signature_placeholder = kwargs.get("signature_placeholder", DEFAULT_PLACEHOLDER_SIGNATURE)

        db = kwargs.get("hash160_lookup", {})
        # we reverse this enumeration to make the behaviour look like the old signer. BRAIN DAMAGE
        for signature_order, sec_key in reversed(list(enumerate(sec_keys))):
            sec_key = solved_values.get(sec_key, sec_key)
            if sec_key in secs_solved:
                continue
            if len(existing_signatures) >= len(signature_variables):
                break
            result = db.get(hash160(sec_key))
            if result:
                secret_exponent = result[0]
                sig_hash = signature_for_hash_type_f(signature_type)
                generator = result[3]
                r, s = generator.sign(secret_exponent, sig_hash)
            else:
                # try existing signatures
                generator = generator_for_signature_type_f(signature_type)
                public_pair = sec_to_public_pair(sec_key, generator=generator)
                for sig in all_signature_hints(public_pair, signature_for_hash_type_f, **kwargs):
                    sig_hash = signature_for_hash_type_f(indexbytes(sig, -1))
                    sig_pair = der.sigdecode_der(sig[:-1])
                    if generator.verify(public_pair, sig_hash, sig_pair):
                        r, s = sig_pair
                        break
                else:
                    continue
            order = generator.order()
            if s + s > order:
                s = order - s
            binary_signature = der.sigencode_der(r, s) + int2byte(signature_type)
            existing_signatures.append((signature_order, binary_signature))

        # pad with placeholder signatures
        if signature_placeholder is not None:
            while len(existing_signatures) < len(signature_variables):
                existing_signatures.append((-1, signature_placeholder))
        existing_signatures.sort()
        return dict(zip(signature_variables, (es[-1] for es in existing_signatures)))
    return (f, m["sig_list"], [a for a in m["sec_list"] if isinstance(a, Atom)])


signing_solver.pattern = ('SIGNATURES_CORRECT', LIST("sec_list"), LIST("sig_list"),
                          CONSTANT("signature_for_hash_type_f"))


def register_all(solver):
    for t in [hash_lookup_solver, constant_equality_solver, signing_solver]:
        solver.register_solver(t.pattern, t)
