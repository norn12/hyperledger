package healthclaimcore

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

const (
	domainSecret    int64 = 101
	domainRecord    int64 = 102
	domainPolicy    int64 = 103
	domainMerkle    int64 = 104
	domainNullifier int64 = 105
)

// HashFields is the native counterpart of the circuit's Poseidon2 Merkle-Damgard
// hash. Every input is encoded as one canonical BN254 scalar field element.
func HashFields(values ...*big.Int) *big.Int {
	h := poseidon.NewMerkleDamgardHasher()
	for _, value := range values {
		var element fr.Element
		element.SetBigInt(value)
		b := element.Bytes()
		_, _ = h.Write(b[:])
	}
	var out fr.Element
	if err := out.SetBytesCanonical(h.Sum(nil)); err != nil {
		panic(err)
	}
	return out.BigInt(new(big.Int))
}

// PolicyDigest commits to fixed-width policy identity, range, and ordered
// diagnosis-set values. Set order and duplicate handling are therefore part of v1.
func PolicyDigest(policyID, labMin, labMax, maxClaim *big.Int, diagnoses [DiagnosisSetSize]*big.Int) *big.Int {
	values := []*big.Int{big.NewInt(domainPolicy), policyID, labMin, labMax, maxClaim}
	values = append(values, diagnoses[:]...)
	return HashFields(values...)
}

func SecretCommitment(secret *big.Int) *big.Int { return HashFields(big.NewInt(domainSecret), secret) }

func RecordLeaf(diagnosis, labValue, policyID, coverageCeiling, secretCommitment *big.Int) *big.Int {
	return HashFields(big.NewInt(domainRecord), diagnosis, labValue, policyID, coverageCeiling, secretCommitment)
}

func MerkleNode(left, right *big.Int) *big.Int {
	return HashFields(big.NewInt(domainMerkle), left, right)
}

func RecordNullifier(secret *big.Int, recordIndex uint64) *big.Int {
	return HashFields(big.NewInt(domainNullifier), secret, new(big.Int).SetUint64(recordIndex))
}

// ValidateCanonical checks scalar values used by public APIs are non-negative
// and below the BN254 scalar modulus.
func ValidateCanonical(v *big.Int) error {
	if v == nil || v.Sign() < 0 || v.Cmp(fr.Modulus()) >= 0 {
		return fmt.Errorf("value is not a canonical BN254 scalar")
	}
	return nil
}
