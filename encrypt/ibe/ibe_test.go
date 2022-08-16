package ibe

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func newSetting() (pairing.Suite, kyber.Point, []byte, kyber.Point) {
	suite := bls.NewBLS12381Suite()
	P := suite.G1().Point().Base()
	s := suite.G1().Scalar().Pick(random.New())
	Ppub := suite.G1().Point().Mul(s, P)

	ID := []byte("passtherand")
	IDP := suite.G2().Point().(kyber.HashablePoint)
	Qid := IDP.Hash(ID)     // public key
	sQid := Qid.Mul(s, Qid) // secret key
	return suite, Ppub, ID, sQid
}

func TestValidTimelockEncryptionDecryptsCorrectly(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)
	msg2, err := Decrypt(suite, sQid, c)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
}

func TestInvalidSigmaFailsDecryption(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.V = []byte("somenonsense")

	_, err = Decrypt(suite, sQid, c)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid proof")
}

func TestInvalidMessageFailsDecryption(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte("somenonsense")
	_, err = Decrypt(suite, sQid, c)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid proof")
}

func TestVeryLongInputFailsEncryption(t *testing.T) {
	suite, Ppub, ID, _ := newSetting()
	msg := []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
	_, err := Encrypt(suite, Ppub, ID, msg)
	require.Error(t, err)
}

func TestVeryLongCipherFailsDecryptionBecauseOfLength(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("hello world")
	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
	_, err = Decrypt(suite, sQid, c)

	require.Error(t, err)
	require.ErrorContains(t, err, "ciphertext too long for the hash function provided")
}

func TestInvalidWFailsDecryptionBecauseOfLength(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("hello world")
	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte(strings.Repeat("A", 25))
	_, err = Decrypt(suite, sQid, c)

	require.Error(t, err)
	require.ErrorContains(t, err, "XorSigma is of invalid length")
}

func TestBackwardsInteropWithTypescript(t *testing.T) {
	suite, _, _, _ := newSetting()

	hexToPoint := func(p kyber.Point, input string) (kyber.Point, error) {
		h, err := hex.DecodeString(input)
		if err != nil {
			return nil, err
		}

		err = p.UnmarshalBinary(h)
		return p, err
	}

	// taken from the testnet round 1
	beacon, err := hexToPoint(
		suite.G2().Point(),
		"86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b",
	)
	require.NoError(t, err)

	// generated using the typescript client at commit `53b562addf179461630b0cc80c0e4ac3436ee4ff`
	U, err := hexToPoint(
		suite.G1().Point(),
		"a5ddec5fa76795d5a28f0869e6a620248c94c112beb8135b11d5614a2b6845c5a4128e3dfe4328d7a6e70b2dea3d7f25",
	)
	require.NoError(t, err)

	V, err := hex.DecodeString("89f0e6cf2b27371017dddeff43ab2263")
	require.NoError(t, err)

	W, err := hex.DecodeString("d767e14f5e3e1738a6c50725c4f0d1b6")
	require.NoError(t, err)

	expectedFileKey, err := hex.DecodeString("deadbeefdeadbeefdeadbeefdeadbeef")
	require.NoError(t, err)

	ciphertext := Ciphertext{U: U, W: W, V: V}

	result, err := Decrypt(suite, beacon, &ciphertext)
	require.NoError(t, err)
	require.Equal(t, expectedFileKey, result)
}
