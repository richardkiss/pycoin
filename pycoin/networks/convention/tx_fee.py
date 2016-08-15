
import io

TX_FEE_PER_THOUSAND_BYTES = 10000


def recommended_fee_for_tx(tx):
    """
    Return the recommended transaction fee in satoshis.
    This is a grossly simplified version of this function.
    TODO: improve to consider TxOut sizes.
      - whether the transaction contains "dust"
      - whether any outputs are less than 0.001
      - update for bitcoind v0.90 new fee schedule
    """
    s = io.BytesIO()
    tx.stream(s)
    tx_byte_count = len(s.getvalue())
    tx_fee = TX_FEE_PER_THOUSAND_BYTES * ((999+tx_byte_count)//1000)
    return tx_fee
