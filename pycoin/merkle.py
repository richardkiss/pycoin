from .encoding.hash import double_sha256
from .encoding.hexbytes import h2b_rev


def merkle(hashes, hash_f=double_sha256):
    """Take a list of hashes, and return the root merkle hash."""
    while len(hashes) > 1:
        hashes = merkle_pair(hashes, hash_f)
    return hashes[0]


def merkle_pair(hashes, hash_f):
    """Take a list of hashes, and return the parent row in the tree of merkle hashes."""
    if len(hashes) % 2 == 1:
        hashes = list(hashes)
        hashes.append(hashes[-1])
    items = []
    for i in range(0, len(hashes), 2):
        items.append(hash_f(hashes[i] + hashes[i+1]))
    return items


def test_merkle():
    s1 = h2b_rev("56dee62283a06e85e182e2d0b421aceb0eadec3d5f86cdadf9688fc095b72510")
    assert merkle([s1], double_sha256) == s1
    # from block 71043
    mr = h2b_rev("30325a06daadcefb0a3d1fe0b6112bb6dfef794316751afc63f567aef94bd5c8")
    s1 = h2b_rev("67ffe41e53534805fb6883b4708fd3744358f99e99bc52111e7a17248effebee")
    s2 = h2b_rev("c8b336acfc22d66edf6634ce095b888fe6d16810d9c85aff4d6641982c2499d1")
    assert merkle([s1, s2], double_sha256) == mr

    # from block 71038
    mr = h2b_rev("4f4c8c201e85a64a410cc7272c77f443d8b8df3289c67af9dab1e87d9e61985e")
    s1 = h2b_rev("f484b014c55a43b409a59de3177d49a88149b4473f9a7b81ea9e3535d4b7a301")
    s2 = h2b_rev("7b5636e9bc6ec910157e88702699bc7892675e8b489632c9166764341a4d4cfe")
    s3 = h2b_rev("f8b02b8bf25cb6008e38eb5453a22c502f37e76375a86a0f0cfaa3c301aa1209")
    assert merkle([s1, s2, s3], double_sha256) == mr


if __name__ == "__main__":
    test_merkle()


"""
Implement Merkle hashing. See http://en.wikipedia.org/wiki/Merkle_tree


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
