import binascii

from ..ecdsa import generator_secp256k1, verify as ecdsa_verify
from ..encoding import public_pair_to_bitcoin_address, sec_to_public_pair
from ..networks import address_prefix_for_netcode
from ..serialize import b2h_rev

from pycoin.tx.pay_to import (
    script_obj_from_script, ScriptMultisig, ScriptPayToAddress, ScriptPayToPublicKey
)
from pycoin.tx.script.check_signature import parse_signature_blob
from pycoin.tx.script.der import UnexpectedDER
from pycoin.tx.script.tools import get_opcode


class NoAddressesForScriptTypeError(Exception):
    pass


def who_signed_tx(tx, tx_in_idx, netcode='BTC'):
    """
    Given a transaction (tx) an input index (tx_in_idx), attempt to figure
    out which addresses where used in signing (so far). This method
    depends on tx.unspents being properly configured. This should work on
    partially-signed MULTISIG transactions (it will return as many
    addresses as there are good signatures).
    Returns a list of ( address, sig_type ) pairs.
    Raises NoAddressesForScriptTypeError if addresses cannot be determined
    for the input's script.
    TODO: This does not yet support P2SH.
    """
    tx_in = tx.txs_in[tx_in_idx]
    parent_tx_out_idx = tx_in.previous_index
    parent_tx_out_script = tx.unspents[tx_in_idx].script
    script_obj = script_obj_from_script(parent_tx_out_script)
    signed_by = []

    if type(script_obj) not in (ScriptPayToAddress, ScriptPayToPublicKey, ScriptMultisig):
        raise NoAddressesForScriptTypeError(
            'unable to determine signing addresses for script type of parent tx {}[{}]'
            .format(b2h_rev(tx_in.previous_hash), parent_tx_out_idx))

    script = tx_in.script
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if data is None:
            continue
        try:
            sig_pair, sig_type = parse_signature_blob(data)
        except (ValueError, TypeError, binascii.Error, UnexpectedDER):
            continue

        sig_hash = tx.signature_hash(parent_tx_out_script, parent_tx_out_idx, sig_type)

        for sec_key in script_obj.sec_keys:
            public_pair = sec_to_public_pair(sec_key)

            if ecdsa_verify(generator_secp256k1, public_pair, sig_hash, sig_pair):
                addr_pfx = address_prefix_for_netcode(netcode)
                addr = public_pair_to_bitcoin_address(public_pair, address_prefix=addr_pfx)
                signed_by.append((addr, sig_type))
    return signed_by
