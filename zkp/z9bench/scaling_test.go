package z9bench

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	poseidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/cmp"
)

// MerkleOnly and PolicyOnly are deliberately isolated component experiments.
// They use the production Poseidon2 gadget and predicates, but omit all other
// HealthClaimHardened gadgets. Their values must not be read as full Z7 costs.
type MerkleOnly struct {
	Root       frontend.Variable `gnark:",public"`
	Leaf       frontend.Variable
	Siblings   []frontend.Variable
	Directions []frontend.Variable
}

func (c *MerkleOnly) Define(api frontend.API) error {
	cur := c.Leaf
	for i := range c.Siblings {
		d := c.Directions[i]
		api.AssertIsBoolean(d)
		left := api.Select(d, c.Siblings[i], cur)
		right := api.Select(d, cur, c.Siblings[i])
		h, err := poseidon2.New(api)
		if err != nil {
			return err
		}
		h.Write(104, left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}

type PolicyOnly struct {
	Commitment frontend.Variable `gnark:",public"`
	Diagnosis  frontend.Variable
	Values     []frontend.Variable
}

func (c *PolicyOnly) Define(api frontend.API) error {
	values := append([]frontend.Variable{103}, c.Values...)
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(values...)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	selectors := make([]frontend.Variable, len(c.Values)-4)
	for i := range selectors {
		selectors[i] = api.IsZero(api.Sub(c.Diagnosis, c.Values[4+i]))
		api.AssertIsBoolean(selectors[i])
	}
	api.AssertIsEqual(sum(api, selectors), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.Values[1], c.Values[2]), 1)
	return nil
}

func sum(api frontend.API, values []frontend.Variable) frontend.Variable {
	if len(values) == 0 {
		return 0
	}
	out := values[0]
	for _, v := range values[1:] {
		out = api.Add(out, v)
	}
	return out
}

func nativePoseidon(values ...*big.Int) *big.Int {
	h := poseidon.NewMerkleDamgardHasher()
	for _, v := range values {
		var x [32]byte
		b := v.Bytes()
		copy(x[32-len(b):], b)
		_, _ = h.Write(x[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return new(big.Int).SetBytes(out[:])
}

func merkleFixture(depth int) (*MerkleOnly, *MerkleOnly) {
	leaf := big.NewInt(987654321)
	siblings := make([]frontend.Variable, depth)
	directions := make([]frontend.Variable, depth)
	cur := leaf
	for i := 0; i < depth; i++ {
		sibling := big.NewInt(int64(500 + i))
		direction := int64(i % 2)
		siblings[i], directions[i] = sibling, direction
		if direction == 0 {
			cur = nativePoseidon(big.NewInt(104), cur, sibling)
		} else {
			cur = nativePoseidon(big.NewInt(104), sibling, cur)
		}
	}
	circuit := &MerkleOnly{Siblings: make([]frontend.Variable, depth), Directions: make([]frontend.Variable, depth)}
	assignment := &MerkleOnly{Root: cur, Leaf: leaf, Siblings: siblings, Directions: directions}
	return circuit, assignment
}

func policyFixture(size int) (*PolicyOnly, *PolicyOnly) {
	values := []frontend.Variable{big.NewInt(12), big.NewInt(3), big.NewInt(8), big.NewInt(1200)}
	for i := 0; i < size; i++ {
		values = append(values, big.NewInt(int64(100+i)))
	}
	diagnosis := values[4+size/2]
	ints := make([]*big.Int, len(values)+1)
	ints[0] = big.NewInt(103)
	for i, v := range values {
		ints[i+1] = v.(*big.Int)
	}
	commit := nativePoseidon(ints...)
	circuit := &PolicyOnly{Values: make([]frontend.Variable, len(values))}
	assignment := &PolicyOnly{Commitment: commit, Diagnosis: diagnosis, Values: values}
	return circuit, assignment
}

type setupResult struct {
	ccs        constraint.ConstraintSystem
	pk         groth16.ProvingKey
	vk         groth16.VerifyingKey
	assignment witness.Witness
	public     witness.Witness
	proof      groth16.Proof
}

func prepare(b *testing.B, circuit, assignment frontend.Circuit) setupResult {
	b.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		b.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		b.Fatal(err)
	}
	return setupResult{ccs: ccs, pk: pk, vk: vk, assignment: w, public: pub, proof: proof}
}

func report(b *testing.B, x setupResult) {
	b.ReportMetric(float64(x.ccs.GetNbConstraints()), "constraints")
	var buf bytes.Buffer
	if _, err := x.proof.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(buf.Len()), "proof_bytes")
}

func BenchmarkMerkleDepth(b *testing.B) {
	for _, depth := range []int{4, 8, 16} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			circuit, assignment := merkleFixture(depth)
			x := prepare(b, circuit, assignment)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := groth16.Prove(x.ccs, x.pk, x.assignment); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			report(b, x)
		})
	}
}

func BenchmarkPolicySize(b *testing.B) {
	for _, size := range []int{4, 8, 16, 32} {
		b.Run(fmt.Sprintf("entries=%d", size), func(b *testing.B) {
			circuit, assignment := policyFixture(size)
			x := prepare(b, circuit, assignment)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := groth16.Prove(x.ccs, x.pk, x.assignment); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			report(b, x)
		})
	}
}

func BenchmarkMerkleVerification(b *testing.B) {
	for _, depth := range []int{4, 8, 16} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			c, a := merkleFixture(depth)
			x := prepare(b, c, a)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := groth16.Verify(x.proof, x.vk, x.public); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			report(b, x)
		})
	}
}

func BenchmarkPolicyVerification(b *testing.B) {
	for _, size := range []int{4, 8, 16, 32} {
		b.Run(fmt.Sprintf("entries=%d", size), func(b *testing.B) {
			c, a := policyFixture(size)
			x := prepare(b, c, a)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := groth16.Verify(x.proof, x.vk, x.public); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			report(b, x)
		})
	}
}
