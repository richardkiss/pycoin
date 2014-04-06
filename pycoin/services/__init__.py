"""
Some simple interfaces to blockchain service providers.
"""

from . import blockchain_info, blockr_io, biteasy

DEFAULT_SERVICE_PROVIDERS = [blockchain_info, biteasy, blockr_io, ]


def spendables_for_address(bitcoin_address, format=None, providers=DEFAULT_SERVICE_PROVIDERS):
    """
    Return a list of Spendable objects for the
    given bitcoin address.

    Set format to "text" or "dict" to transform return value
    from an object to a string or dict.

    This is intended to be a convenience function. There is no way to know that
    the list returned is a complete list of spendables for the address in question.

    You can verify that they really do come from the existing transaction
    by calling tx_utils.validate_unspents.
    """
    for p in providers:
        print(p)
        try:
            spendables = p.spendables_for_address(bitcoin_address)
            if format:
                method = "as_%s" % format
                spendables = [getattr(s, method)() for s in spendables]
            return spendables
        except Exception:
            pass
    return None
