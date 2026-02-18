# Annotated pycoin/merkle.py

from typing import List, Optional

class MerkleNode:
    def __init__(self, left: Optional['MerkleNode'], right: Optional['MerkleNode'], value: bytes):
        self.left = left
        self.right = right
        self.value = value

def create_merkle_tree(leaves: List[bytes]) -> MerkleNode:
    nodes = [MerkleNode(None, None, leaf) for leaf in leaves]
    while len(nodes) > 1:
        nodes = [MerkleNode(nodes[i], nodes[i + 1], nodes[i].value + nodes[i + 1].value)
                  for i in range(0, len(nodes), 2)]
    return nodes[0] if nodes else None
