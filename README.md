# nr-merkletree
Python-3 compatible Merkle tree implementation.

#### Current Stable Version
```
0.1.3
```


# Install

### Pip
```
pip install nr-merkletree
```

### Development Installation
* Clone the project.
* Install in Anaconda3 environment
	```
	$ conda env create --force -f dev_environment.yml
	$ source activate nr-merkletree
	$ pip install -e .
	```


# Test
To run the tests:
```
make test
```


# Usage
```python
from nr_merkletree import MerkleTree
from pprint import pprint

# A list of bytes data
data_chunks = [b'0', b'1', b'2', b'3', b'4']

# Create merkle_tree
merkle_tree = MerkleTree(data_chunks)

# Print out Merkle Tree
pprint(merkle_tree.tree.to_dict())
```


# Examples
```
$ python examples/simple_merkle_tree.py
```


# License
MIT
