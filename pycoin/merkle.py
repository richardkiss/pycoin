
from .encoding import double_sha256

def merkle(hashes, hash_f=double_sha256):
    while len(hashes) > 1:
        hashes = merkle_pair(hashes, hash_f)
    return hashes[0]

def merkle_pair(hashes, hash_f):
    if len(hashes) % 2 == 1:
        hashes = list(hashes)
        hashes.append(hashes[-1])
    l = []
    for i in range(0, len(hashes), 2):
        l.append(hash_f(hashes[i] + hashes[i+1]))
    return l

def test_merkle():
    import binascii
    def to_bin(s):
        return bytes(reversed(binascii.unhexlify(s)))
    s1 = to_bin("56dee62283a06e85e182e2d0b421aceb0eadec3d5f86cdadf9688fc095b72510")
    assert merkle([s1], double_sha256) == s1
    # from block 71043
    mr = to_bin("30325a06daadcefb0a3d1fe0b6112bb6dfef794316751afc63f567aef94bd5c8")
    s1 = to_bin("67ffe41e53534805fb6883b4708fd3744358f99e99bc52111e7a17248effebee")
    s2 = to_bin("c8b336acfc22d66edf6634ce095b888fe6d16810d9c85aff4d6641982c2499d1")
    assert merkle([s1, s2], double_sha256) == mr

    # from block 71038
    mr = to_bin("4f4c8c201e85a64a410cc7272c77f443d8b8df3289c67af9dab1e87d9e61985e")
    s1 = to_bin("f484b014c55a43b409a59de3177d49a88149b4473f9a7b81ea9e3535d4b7a301")
    s2 = to_bin("7b5636e9bc6ec910157e88702699bc7892675e8b489632c9166764341a4d4cfe")
    s3 = to_bin("f8b02b8bf25cb6008e38eb5453a22c502f37e76375a86a0f0cfaa3c301aa1209")
    assert merkle([s1, s2, s3], double_sha256) == mr

if __name__ == "__main__":
    test_merkle()
