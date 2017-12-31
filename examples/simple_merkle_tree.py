from pprint import pprint

from nr_merkletree import MerkleTree

# Create a list of data_chunks which are of type bytes
data_chunks = [str(i).encode() for i in range(5)]
print("\n##### DATA CHUNKS #####\n{}\n".format(data_chunks))

# Create merkle_tree out of the data_chunks
merkle_tree = MerkleTree(data_chunks=data_chunks)

# Print merkle_tree
print("\n##### MERKLE TREE #####")
pprint(merkle_tree.tree.to_dict())
