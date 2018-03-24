# generic solver

import pdb

from pycoin.satoshi.checksigops import parse_signature_blob
from ..serialize import b2h

from pycoin.encoding.exceptions import EncodingError
from pycoin.encoding.hash import hash160
from pycoin.encoding.sec import public_pair_to_sec, sec_to_public_pair
from pycoin.intbytes import indexbytes, int2byte
from pycoin.tx.exceptions import SolvingError
from pycoin.satoshi import der

from .constraints import Atom, Operator


DEFAULT_PLACEHOLDER_SIGNATURE = b''
DEFAULT_SIGNATURE_TYPE = 1


SOLUTIONS_BY_CONSTRAINT = []


def register_solver(solver_f):
    global SOLUTIONS_BY_CONSTRAINT
    SOLUTIONS_BY_CONSTRAINT.append(solver_f)


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
        except (ValueError, EncodingError, der.UnexpectedDER):
            # if public_pair is invalid, we just ignore it
            pass
    return signatures, secs_solved


def constraint_matches(c, m):
    """
    Return dict noting the substitution values (or False for no match)
    """
    if isinstance(m, tuple):
        d = {}
        if isinstance(c, Operator) and c._op_name == m[0]:
            for c1, m1 in zip(c._args, m[1:]):
                r = constraint_matches(c1, m1)
                if r is False:
                    return r
                d.update(r)
            return d
        return False
    return m.match(c)


class CONSTANT(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if not isinstance(c, Atom):
            return {self._name: c}
        return False


class VAR(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if isinstance(c, Atom) and not isinstance(c, Operator):
            return {self._name: c}
        return False


class LIST(object):
    def __init__(self, name):
        self._name = name

    def match(self, c):
        if isinstance(c, (tuple, list)):
            return {self._name: c}
        return False


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
register_solver(hash_lookup_solver)


def constant_equality_solver(m):

    def f(solved_values, **kwargs):
        return {m["var"]: m["const"]}

    return (f, [m["var"]], ())


constant_equality_solver.pattern = ('EQUAL', VAR("var"), CONSTANT('const'))
register_solver(constant_equality_solver)


def signing_solver(m):
    def f(solved_values, **kwargs):
        signature_type = kwargs.get("signature_type", DEFAULT_SIGNATURE_TYPE)
        signature_hints = kwargs.get("signature_hints", [])
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
                for sig in signature_hints:
                    sig_hash = signature_for_hash_type_f(indexbytes(sig, -1))
                    generator = generator_for_signature_type_f(signature_type)
                    public_pair = sec_to_public_pair(sec_key, generator=generator)
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
register_solver(signing_solver)


def solutions_for_constraint(c):
    # given a constraint c
    # return None or
    # a solution (solution_f, target atom, dependency atom list)
    # where solution_f take list of solved values

    for f_factory in SOLUTIONS_BY_CONSTRAINT:
        m = constraint_matches(c, f_factory.pattern)
        if m:
            return f_factory(m)
