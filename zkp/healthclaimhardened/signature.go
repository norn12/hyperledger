package healthclaimhardened

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// SignLeaf signs the canonical field encoding of a record leaf with BN254
// twisted-Edwards EdDSA and MiMC-FS, matching gnark's in-circuit gadget.
func SignLeaf(key *eddsa.PrivateKey, leaf *big.Int) ([]byte, error) {
	var message fr.Element
	message.SetBigInt(leaf)
	b := message.Bytes()
	h := mimc.NewMiMC()
	return key.Sign(b[:], h)
}
