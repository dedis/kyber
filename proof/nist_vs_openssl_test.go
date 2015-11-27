package proof

import (
    "encoding/hex"
    "fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/nist"
    "testing"
)

func runExample(suite abstract.Suite) {
    M := "Hello World!"
	rand := suite.Cipher([]byte("example"))
    B := suite.Point().Base()
    x := suite.Secret().Pick(rand)
    X := suite.Point().Mul(nil, x)
    rep := Rep("X", "x", "B")
	sec := map[string]abstract.Secret{"x": x}
	pub := map[string]abstract.Point{"B": B, "X": X}
	prover := rep.Prover(suite, sec, pub, nil)
	proof, _ := HashProve(suite, M, rand, prover)
	fmt.Print("Signature:\n" + hex.Dump(proof))
}


func TestHashProve_1 (t *testing.T) {
    runExample(nist.NewAES128SHA256P256())
    runExample(openssl.NewAES128SHA256P256())
}
