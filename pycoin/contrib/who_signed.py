import binascii

from ..coins.bitcoin.ScriptStreamer import BitcoinScriptStreamer  # BRAIN DAMAGE
from ..coins.bitcoin.SolutionChecker import BitcoinSolutionChecker  # BRAIN DAMAGE
from ..ecdsa.secp256k1 import secp256k1_generator
from ..encoding import public_pair_to_bitcoin_address, sec_to_public_pair, EncodingError
from ..networks import address_prefix_for_netcode

from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.satoshi.der import UnexpectedDER


class NoAddressesForScriptTypeError(Exception):
    pass


def sec_keys(script):
    pc = 0
    opcode, data, pc = BitcoinScriptStreamer.get_opcode(script, pc)
    sec_keys = []
    while pc < len(script):
        opcode, data, pc = BitcoinScriptStreamer.get_opcode(script, pc)
        if data:
            try:
                sec_to_public_pair(data, secp256k1_generator)
                sec_keys.append(data)
            except EncodingError:
                pass
    return sec_keys


def who_signed_tx(tx, tx_in_idx, netcode='BTC'):
    """
    Given a transaction (tx) an input index (tx_in_idx), attempt to figure
    out which addresses where used in signing (so far). This method
    depends on tx.unspents being properly configured. This should work on
    partially-signed MULTISIG transactions (it will return as many
    addresses as there are good signatures).
    Returns a list of ( address, sig_type ) pairs.
    """
    tx_in = tx.txs_in[tx_in_idx]
    parent_tx_out_idx = tx_in.previous_index
    parent_tx_out_script = tx.unspents[tx_in_idx].script
    signed_by = []

    script = tx_in.script
    pc = 0
    while pc < len(script):
        opcode, data, pc = BitcoinScriptStreamer.get_opcode(script, pc)
        if data is None:
            continue
        try:
            sig_pair, sig_type = parse_signature_blob(data)
        except (ValueError, TypeError, binascii.Error, UnexpectedDER):
            continue

        sc = BitcoinSolutionChecker(tx)
        if sc.is_pay_to_script_hash(parent_tx_out_script):
            tx_context = sc.tx_context_for_idx(tx_in_idx)
            stack, solution_stack = sc._check_solution(tx_context, flags=0, traceback_f=None)
            parent_tx_out_script = solution_stack[-1]

        sig_hash = sc.signature_hash(parent_tx_out_script, parent_tx_out_idx, sig_type)

        for sec_key in sec_keys(parent_tx_out_script):
            public_pair = sec_to_public_pair(sec_key, secp256k1_generator)

            if secp256k1_generator.verify(public_pair, sig_hash, sig_pair):
                addr_pfx = address_prefix_for_netcode(netcode)
                addr = public_pair_to_bitcoin_address(public_pair, address_prefix=addr_pfx)
                signed_by.append((addr, sig_type))
    return signed_by
