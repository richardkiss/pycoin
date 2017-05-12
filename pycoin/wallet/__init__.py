
# a wallet is a DB of Spendable objects, and a way to query and manage them

# The wallet accepts pycoinnet bitcoin events (_blockchain_update and _mempool_tx)
# and decides for itself which Spendable objects its interested in.

# Ideally, it should keep an archive of all Spendable objects its ever received so it can
# handle as many _blockchain_update rollbacks as it would like to.

# It should also keep a DB of all the transactions it's ever created, so it can watch for
# morphed versions (modulo malleability)
