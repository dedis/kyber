package tbls

import (
	"fmt"
	"testing"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/share"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	g2s := bn256.NewSingleGroupSuite(suite.G2())
	n := 10
	t := n/2 + 1
	secret := g2s.Scalar().Pick(random.New())
	priPoly := share.NewPriPoly(g2s, t, secret)
	pubPoly := priPoly.Commit(g2s.Point().Base())
	fmt.Println(pubPoly.Commit())
	sigShares := make([][]byte, n)
	for i, x := range priPoly.Shares(n) {
		sigShares[i], err = Sign(suite, x, msg)
		require.Nil(test, err)
		//err = Verify(suite, pubPoly, msg, sigShares[i])
		//require.Nil(test, err)
	}
	sig, err := Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)

	//pubG1 := priPoly.Commit()

	//for i, s := range pubShares {

	//}

	require.Nil(test, bls.Verify(suite, pubPoly.Commit(), msg, sig))
}
