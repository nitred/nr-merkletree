"""Basic Test."""
import hashlib

from nr_merkletree import MerkleTree


def test_basic():
    """Test if MerkleTree works for a very example."""
    data_chunks = [b'0', b'1']
    merkle_tree = MerkleTree(data_chunks)

    expected_hash0 = hashlib.sha256(data_chunks[0]).digest()
    expected_hash1 = hashlib.sha256(data_chunks[1]).digest()
    expected_root_hash = hashlib.sha256(expected_hash0 + expected_hash1).digest()

    assert merkle_tree.tree.get_node(nid=expected_hash0).identifier == expected_hash0
    assert merkle_tree.tree.get_node(nid=expected_hash1).identifier == expected_hash1
    assert merkle_tree.tree.get_node(nid=expected_root_hash).identifier == expected_root_hash
