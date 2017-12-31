# TODO: Documentation
import hashlib
from itertools import zip_longest
from pprint import pprint

from treelib import Node, Tree


class MerkleTree(object):
    # TODO: Documentation
    # TODO: Inherit treelib.Tree
    # TODO: Add logging
    # TODO: Hexify
    # TODO: Proof

    def __init__(self, data_chunks):
        # print("__init__")
        self.create_leaf_nodes(data_chunks)

        self.register_tree()
        self.build_tree(self.leaf_nodes)

    def hash_function(self, data):
        # print("hash_function: {}".format(type(data)))
        # TODO: Better validation.
        assert isinstance(data, bytes), "data must be bytes inorder to be hashed."
        # TODO: Lookup what the best hash functions are. Currently using sha256
        data_hash = hashlib.sha256()
        data_hash.update(data)
        return data_hash.digest()

    def create_leaf_nodes(self, data_chunks):
        # print("create_leaf_nodes")
        # TODO: Identifier should be HASH
        self.leaf_nodes = [Node(tag=str(i),
                                identifier=self.hash_function(data_chunk),
                                data=data_chunk)
                           for i, data_chunk in enumerate(data_chunks)]

    def register_tree(self):
        self.tree = Tree()

    def get_node_pair_iterator(self, nodes):
        return zip_longest(nodes[::2], nodes[1::2])

    def get_parent_node_from_node_pair(self, node_a, node_b):
        if node_b is not None:
            parent_node = Node(tag=node_a.tag + node_b.tag,
                               identifier=self.hash_function(node_a.identifier + node_b.identifier))
        else:
            parent_node = Node(tag=node_a.tag + 'x',
                               identifier=self.hash_function(node_a.identifier))

        print("get_parent_node_from_node_pair: {}".format(parent_node.tag))
        return parent_node

    def build_tree(self, nodes):
        # When root node
        if len(nodes) == 1:
            root_node = nodes[0]
            print("build_tree: root    : {}".format(root_node.tag))
            self.tree.add_node(node=root_node, parent=None)

        # When not root node
        else:
            print("build_tree: non-root: {}".format(", ".join(node.tag for node in nodes)))
            # Get parents of node pairs
            parent_nodes = [self.get_parent_node_from_node_pair(node_a, node_b)
                            for node_a, node_b in self.get_node_pair_iterator(nodes)]

            # Add parents to tree
            self.build_tree(parent_nodes)

            # Update parents with their pair of children
            for parent_node, (node_a, node_b) in zip(parent_nodes, self.get_node_pair_iterator(nodes)):
                # Add node_a as a child of parent_node
                self.tree.add_node(node=node_a, parent=parent_node)

                # Add node_b as a child of parent_node, only if None. It can be None if len(leaf_nodes) is odd.
                if node_b is not None:
                    self.tree.add_node(node=node_b, parent=parent_node)
