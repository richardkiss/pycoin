import hashlib
import os

import pycoin.contrib.ripemd160

from .hexbytes import bytes_as_revhex


def ripemd160_native(data):
    return hashlib.new("ripemd160", data)


def get_best_ripemd160():
    # ubuntu 22 features an openssl without ripemd160, where python gets its
    # implementation from. To top it off, `"ripemd160" in hashlib.algorithms_available`
    # still evaluates to true, so we actually have to try it to see if we'll fail.

    USE_NATIVE = "ripemd160" in hashlib.algorithms_available and not os.getenv(
        "PYCOIN_USE_PYTHON_RIPEMD160"
    )

    if USE_NATIVE:
        try:
            ripemd160_native(b"").digest()
            return ripemd160_native
        except Exception:
            pass

    # stupid Google App Engine hashlib doesn't support ripemd160 for some stupid reason
    # import it from pycrypto. You need to add
    # - name: pycrypto
    #   version: "latest"
    # to the "libraries" section of your app.yaml
    try:
        from Crypto.Hash.RIPEMD import RIPEMD160Hash
    except Exception:

        class RIPEMD160Hash:
            def __init__(self, data):
                self._digest = pycoin.contrib.ripemd160.ripemd160(data)

            def digest(self):
                return self._digest

    return RIPEMD160Hash


ripemd160 = get_best_ripemd160()


def double_sha256(data):
    """A standard compound hash."""
    return bytes_as_revhex(hashlib.sha256(hashlib.sha256(data).digest()).digest())


def hash160(data):
    """A standard compound hash."""
    return ripemd160(hashlib.sha256(data).digest()).digest()


"""
The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
