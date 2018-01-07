"""Module for Merkle Tree."""
import hashlib
from itertools import zip_longest

from treelib import Node, Tree
from treelib.exceptions import NodeIDAbsentError


class MerkleTree(Tree):
    """Merkle Tree. Inherits treelib.Tree class.

    All nodes of the tree are of type treelib.Node. The `data_chunks` are first
    converted to leaf nodes, where each node is assigned an SHA256 Pseudo Unique
    ID and its index is assigned as the tag.
    """

    # TODO: Add logging
    # TODO: Hexify
    # TODO: Proof
    # TODO: Catch exception for tree having a repeated hash.

    def __init__(self, data_chunks):
        """Initialize with a list of data_chunks.

        Args:
            data_chunks (iter of bytes): An iterable (list, tuple, etc) of bytes data.
        """
        # Validation.
        try:
            iter(data_chunks)
        except TypeError as e:
            raise TypeError("`data_chunks` argument must be an iterable instead of type {}.".format(type(data_chunks)))

        # Initialize parent treelib.Tree()
        super().__init__()

        self.leaf_nodes = self.__create_leaf_nodes(data_chunks)
        self.__build_tree(self.leaf_nodes)

    def hash(self, data):
        """Apply a hashing function on bytes data and return the hash.

        Args:
            data (bytes): Bytes data on which to apply the hashing function.

        Returns:
            bytes (hash): The hash output of the hashing function.
        """
        # Validation.
        if not isinstance(data, bytes):
            raise TypeError("`data` argument must be of type `bytes` instead of type {}.".format(type(data)))

        # TODO: Lookup what the best hash functions are. Currently using sha256.
        return hashlib.sha256(data).digest()

    def __create_leaf_nodes(self, data_chunks):
        """Convert data_chunks into leaf nodes of type `treelib.Node`.

        Each node is assigned a SHA256 pseudo unique `identifier`.
        Each node is assigned its index in the list as the `tag`.

        Args:
            data_chunks (iter of bytes): An iterable (list, tuple, etc) of bytes data.
                Validated already.

        Returns:
            list of treelib.Node: Leaf nodes.
        """
        leaf_nodes = [Node(tag=str(i),
                           identifier=self.hash(data_chunk),
                           data=data_chunk)
                      for i, data_chunk in enumerate(data_chunks)]
        return leaf_nodes

    def __get_node_pair_iterator(self, nodes):
        """Return an iterator of pairs of nodes from the original nodes iterable.

        If `len(nodes)` is odd then the last pair of nodes will contain a `None`
        as the second node in the pair i.e. if `(node_a, node_b)` is the last
        pair then `node_b` will be None. If `len(nodes)` is even then it just
        returns the full pairs.

        Args:
            nodes (list of treelib.Node): List of nodes to return pairs from.

        Returns:
            iterator: Pair of nodes `(node_a, node_b)`.
        """
        return zip_longest(nodes[::2], nodes[1::2])

    def __get_parent_node_from_node_pair(self, node_a, node_b):
        """Return a parent node from two children nodes by hasing their hashes.

        The parent node's identifier will be the hash of the concatenated hashes
        of the children's nodes in order to make it a Merkle Tree structure.

        The parent node's tag is also formed by just concatenating the children
        nodes' tags together. In case node_b is `None` then the parent tag will
        be the concatenation of node_a's tag with string "x".

        Args:
            node_a (treelib.Node): First node in the pair of children nodes.
            node_b (treelib.Node): Second node in the pair of children nodes.
                It is possible that node_b might be `None` in the case that there
                are odd number of total children nodes.

        Returns:
            treelib.Node: Parent node conforming to the Merkle Tree.
        """
        if node_b is not None:
            parent_node = Node(tag=node_a.tag + node_b.tag,
                               identifier=self.hash(node_a.identifier + node_b.identifier))
        else:
            parent_node = Node(tag=node_a.tag + 'x',
                               identifier=self.hash(node_a.identifier))

        print("__get_parent_node_from_node_pair: {}".format(parent_node.tag))
        return parent_node

    def __build_tree(self, nodes):
        """Recursively build the Merkle Tree from the leaf nodes.

        treelib.Tree requires that the Nodes should be added from the top-down i.e.
        the root-node should be added first. But since the root-node is calculated
        last in the Merkle Tree, we will use recursion to achieve this such that
        the root node is added to the tree on the final iteraton of the recursion,
        and then children nodes are added subsequently until we reach the first
        iteraton in reverse-order where the leaf nodes are added.

        Args:
            nodes (list of treelib.Node): List of nodes on which to build the
                Merkle Tree.

        Returns:
            None: Starting in reverse-order with the final iteration, the root-node
                is added first to the tree followed by all it's children to form
                the Merkle Tree.
        """
        # If the length of the nodes is 1, then it is the root node.
        if len(nodes) == 1:
            root_node = nodes[0]
            print("__build_tree: root    : {}".format(root_node.tag))
            self.add_node(node=root_node, parent=None)

        # Else the nodes are not root, and their parent nodes need to be calculated.
        else:
            print("__build_tree: non-root: {}".format(", ".join(node.tag for node in nodes)))

            # Each parent node is calculated on a pair of nodes.
            parent_nodes = [self.__get_parent_node_from_node_pair(node_a, node_b)
                            for node_a, node_b in self.__get_node_pair_iterator(nodes)]

            # Recursively call the `__build_tree` function again for the `parent_nodes`,
            # to find the parents of the `parent_nodes` and so on until the root node is
            # found. Once the root node is found, it is added to the tree. Then its children
            # are added to the tree and so on until the `parent_nodes` are added to the tree.
            # NOTE: TL-DR; Once this function returns, we can assume that the `parent_nodes`
            # have been added to the tree.
            self.__build_tree(parent_nodes)

            # NOTE: Explicitly add the children of the `parent_nodes` to the tree.
            for parent_node, (node_a, node_b) in zip(parent_nodes, self.__get_node_pair_iterator(nodes)):
                # Add node_a as a child of parent_node
                self.add_node(node=node_a, parent=parent_node)

                # Add node_b as a child of parent_node, if not None. It is None if `len(nodes)` is odd.
                if node_b is not None:
                    self.add_node(node=node_b, parent=parent_node)

    def __get_children_pair_nodes_from_parent(self, parent_node):
        """Return a pair of children of parent node.

        * Return child_a, child_b if both exist.
        * Return child_a, None    if one exists.
        * Raise error for other cases.
        """
        child_nodes = self.children(parent_node.identifier)

        if len(child_nodes) == 2:
            return child_nodes[0], child_nodes[1]
        elif len(child_nodes) == 1:
            return child_nodes[0], None
        else:
            raise Exception("Parent with incorrect number of children.")

    def __verify_node_children_hashes(self, node):
        """Verify that the node identifier is the hash of children identifiers."""
        node_a, node_b = self.__get_children_pair_nodes_from_parent(node)

        # If parent has two children.
        if node_b is not None:
            if self.hash(node_a.identifier + node_b.identifier) == node.identifier:
                return True
            else:
                return False
        # If parent has only one child.
        else:
            if self.hash(node_a.identifier) == node.identifier:
                return True
            else:
                return False

    def __verify_node_parent_pointers(self, node):
        """Verify if the node is the child of its parent.

        * Check if the node has a parent.
        * Check if the node is a child of the parent.
        """
        # Check if node has a parent.
        try:
            parent_node = self.parent(node.identifier)
        except NodeIDAbsentError as ex:
            return False

        # Check if node is a child of parent_node.
        node_a, node_b = self.__get_children_pair_nodes_from_parent(parent_node)

        if node_a.identifier == node.identifier:
            return True
        elif (node_b is not None) and (node_b.identifier == node.identifier):
            return True
        else:
            return False

    def __prove_node_membership_recursively(self, node):
        """Recursively prove if the node belongs to the merkle tree.

        To prove a node's membership, the following checks are done:
            * If the node's children have the right hashes.
            * If the node is the child of its parent (by checking pointers).
            * Recursively prove the node's parent's membership.

        Args:
            node (treelib.Node): The node which needs its membership proven.

        Returns:
            bool (proof of membership): Whether the node is a member or not.
        """
        # If root, only verify children.
        if node.is_root():
            return self.__verify_node_children_hashes(node)

        # If lead, only verify parent.
        elif node.is_leaf():
            if not self.__verify_node_parent_pointers(node):
                return False

            # Recursive parent call.
            parent = self.parent(nid=node.identifier)
            return self.__prove_node_membership_recursively(parent)

        # If regular node, verify children and then parents.
        else:
            if not self.__verify_node_children_hashes(node):
                return False

            if not self.__verify_node_parent_pointers(node):
                return False

            # Recursive parent call.
            parent = self.parent(nid=node.identifier)
            return self.__prove_node_membership_recursively(parent)

    def prove_membership(self, data_chunk):
        """Prove whether a data_chunk is a member of this Merkle Tree.

        The following checks are done to prove membership:
            * check if data_chunk exists in tree.
            * check if data_chunk_node is a leaf node.
            * Recursively check parent nodes.
        """
        nid = self.hash(data_chunk)

        # check if node exists in tree.
        node = self.get_node(nid)
        if node is None:
            return False

        # check if node is a leaf node.
        if not node.is_leaf():
            return False

        # prove node membership.
        if not self.__prove_node_membership_recursively(node):
            return False

        # If all checks pass, return True.
        return True
