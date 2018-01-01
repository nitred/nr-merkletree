"""Basic Test."""
import hashlib

import pytest
from nr_merkletree import MerkleTree


def test_basic():
    """Test if MerkleTree works for a basic example."""
    data_chunks = [b'0', b'1', b'2']
    merkle_tree = MerkleTree(data_chunks)

    expected_hash0 = hashlib.sha256(data_chunks[0]).digest()
    expected_hash1 = hashlib.sha256(data_chunks[1]).digest()
    expected_hash2 = hashlib.sha256(data_chunks[2]).digest()
    expected_hash01 = hashlib.sha256(expected_hash0 + expected_hash1).digest()
    expected_hash2x = hashlib.sha256(expected_hash2).digest()
    expected_root_hash = hashlib.sha256(expected_hash01 + expected_hash2x).digest()

    assert merkle_tree.get_node(nid=expected_hash0).identifier == expected_hash0
    assert merkle_tree.get_node(nid=expected_hash1).identifier == expected_hash1
    assert merkle_tree.get_node(nid=expected_hash1).identifier == expected_hash1
    assert merkle_tree.get_node(nid=expected_hash01).identifier == expected_hash01
    assert merkle_tree.get_node(nid=expected_hash2x).identifier == expected_hash2x
    assert merkle_tree.get_node(nid=expected_root_hash).identifier == expected_root_hash

    # Sanity check.
    with pytest.raises(AttributeError):
        assert merkle_tree.get_node(nid=b'not_an_expected_hash').identifier
