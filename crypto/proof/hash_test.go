package proof

import (
	"fmt"
	"encoding/hex"
	"dissent/crypto"
	"dissent/crypto/openssl"
)


// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!"			// message we want to sign
	rep := Rep("X","x","B")
	sec := map[string]crypto.Secret{"x":x}
	pub := map[string]crypto.Point{"B":B, "X":X}
	prover := rep.Prover(suite, sec, pub, nil)
	proof,_ := HashProve(suite, M, rand, prover)
	fmt.Print("Signature:\n"+hex.Dump(proof))

	// Verify the signature against the correct message M.
	verifier := rep.Verifier(suite, pub)
	err := HashVerify(suite, M, verifier, proof)
	if err != nil {
		panic("signature failed to verify!")
	}
	fmt.Println("Signature verified against correct message M.")

	// Now verify the signature against the WRONG message.
	BAD := "Goodbye World!"
	verifier = rep.Verifier(suite, pub)
	err = HashVerify(suite, BAD, verifier, proof)
	fmt.Println("Signature verify against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  02 a7 88 0a 50 7e 71 48  03 0d a8 6c 31 f7 01 ed  |....P~qH...l1...|
	// 00000010  c5 ea 92 5a b3 35 85 42  43 ec b2 72 1c 50 10 88  |...Z.5.BC..r.P..|
	// 00000020  fe 72 86 62 f3 a6 3a 80  57 12 ff bf b6 1f 76 c5  |.r.b..:.W.....v.|
	// 00000030  dd e1 5e e6 7b 4b ac 0a  60 6f 1e 07 cd 52 43 07  |..^.{K..`o...RC.|
	// 00000040  d2                                                |.|
	// Signature verified against correct message M.
	// Signature verify against wrong message: invalid proof: commit mismatch
}

