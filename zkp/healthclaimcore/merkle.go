package healthclaimcore

import "math/big"

// MerklePath is a fixed-depth Poseidon2 membership witness. Direction 0 means
// current node is left; direction 1 means current node is right.
type MerklePath struct {
	Siblings   [MerkleDepth]*big.Int
	Directions [MerkleDepth]*big.Int
}

// RootFromPath computes the native root and rejects malformed directions.
func RootFromPath(leaf *big.Int, path MerklePath) *big.Int {
	current := new(big.Int).Set(leaf)
	for i := 0; i < MerkleDepth; i++ {
		if path.Directions[i].Sign() != 0 && path.Directions[i].Cmp(big.NewInt(1)) != 0 {
			panic("Merkle direction must be Boolean")
		}
		if path.Directions[i].Uint64() == 0 {
			current = MerkleNode(current, path.Siblings[i])
		} else {
			current = MerkleNode(path.Siblings[i], current)
		}
	}
	return current
}

// IndexFromDirections decodes the fixed-depth little-endian path directions.
func IndexFromDirections(path MerklePath) uint64 {
	var index uint64
	for i, direction := range path.Directions {
		if direction.Uint64() == 1 {
			index |= 1 << i
		}
	}
	return index
}
