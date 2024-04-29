package ibe

/*

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	bls "go.dedis.ch/kyber/v3/pairing/circl_bls12381"
	"go.dedis.ch/kyber/v3/util/random"
)

func newSetting(i uint) (
	pairing.Suite, kyber.Point, []byte, kyber.Point,
	func(s pairing.Suite, master kyber.Point, ID []byte, msg []byte) (*Ciphertext, error),
	func(s pairing.Suite, private kyber.Point, c *Ciphertext) ([]byte, error),
) {
	if !(i == 1 || i == 2) {
		panic("invalid test")
	}
	if i == 1 {
		suite := bls.NewSuiteBLS12381()
		P := suite.G1().Point().Base()
		s := suite.G1().Scalar().Pick(random.New())
		Ppub := suite.G1().Point().Mul(s, P)

		ID := []byte("passtherand")
		IDP := suite.G2().Point().(kyber.HashablePoint)
		Qid := IDP.Hash(ID)     // public key
		sQid := Qid.Mul(s, Qid) // secret key
		return suite, Ppub, ID, sQid, EncryptCCAonG1, DecryptCCAonG1
	}
	// i == 2
	suite := bls.NewSuiteBLS12381()
	P := suite.G2().Point().Base()
	s := suite.G2().Scalar().Pick(random.New())
	Ppub := suite.G2().Point().Mul(s, P)

	ID := []byte("passtherand")
	IDP := suite.G1().Point().(kyber.HashablePoint)
	Qid := IDP.Hash(ID)     // public key
	sQid := Qid.Mul(s, Qid) // secret key
	return suite, Ppub, ID, sQid, EncryptCCAonG2, DecryptCCAonG2
}

func TestValidEncryptionDecrypts(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(1)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)
		msg2, err := decrypt(suite, sQid, c)
		require.NoError(t, err)
		require.Equal(t, msg, msg2)
	})

	t.Run("OnG2", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(2)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)
		msg2, err := decrypt(suite, sQid, c)
		require.NoError(t, err)
		require.Equal(t, msg, msg2)
	})
}

func TestInvalidSigmaFailsDecryption(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {

		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(1)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.V = []byte("somenonsense")

		_, err = decrypt(suite, sQid, c)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid proof")
	})

	t.Run("OnG2", func(t *testing.T) {

		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(2)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.V = []byte("somenonsense")

		_, err = decrypt(suite, sQid, c)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid proof")
	})
}

func TestInvalidMessageFailsDecryption(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(1)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte("somenonsense")
		_, err = decrypt(suite, sQid, c)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid proof")
	})

	t.Run("OnG2", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(2)
		msg := []byte("Hello World\n")

		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte("somenonsense")
		_, err = decrypt(suite, sQid, c)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid proof")
	})
}

func TestVeryLongInputFailsEncryption(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {
		suite, Ppub, ID, _, encrypt, _ := newSetting(1)
		msg := []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
		_, err := encrypt(suite, Ppub, ID, msg)
		require.Error(t, err)

	})
	t.Run("OnG2", func(t *testing.T) {
		suite, Ppub, ID, _, encrypt, _ := newSetting(2)
		msg := []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
		_, err := encrypt(suite, Ppub, ID, msg)
		require.Error(t, err)
	})
}

func TestVeryLongCipherFailsDecryptionBecauseOfLength(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(1)
		msg := []byte("hello world")
		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
		_, err = decrypt(suite, sQid, c)

		require.Error(t, err)
		require.ErrorContains(t, err, "ciphertext too long for the hash function provided")
	})
	t.Run("OnG2", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(2)
		msg := []byte("hello world")
		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
		_, err = decrypt(suite, sQid, c)

		require.Error(t, err)
		require.ErrorContains(t, err, "ciphertext too long for the hash function provided")
	})
}

func TestInvalidWFailsDecryptionBecauseOfLength(t *testing.T) {
	t.Run("OnG1", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(1)
		msg := []byte("hello world")
		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte(strings.Repeat("A", 25))
		_, err = decrypt(suite, sQid, c)

		require.Error(t, err)
		require.ErrorContains(t, err, "XorSigma is of invalid length")
	})
	t.Run("OnG2", func(t *testing.T) {
		suite, Ppub, ID, sQid, encrypt, decrypt := newSetting(2)
		msg := []byte("hello world")
		c, err := encrypt(suite, Ppub, ID, msg)
		require.NoError(t, err)

		c.W = []byte(strings.Repeat("A", 25))
		_, err = decrypt(suite, sQid, c)

		require.Error(t, err)
		require.ErrorContains(t, err, "XorSigma is of invalid length")
	})
}

func TestBackwardsInteropWithTypescript(t *testing.T) {
	t.Skip("Typescript library not yet updated to support both G2 keys")
	suite, _, _, _, _, decrypt := newSetting(1)

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

	result, err := decrypt(suite, beacon, &ciphertext)
	require.NoError(t, err)
	require.Equal(t, expectedFileKey, result)
}

func TestCPAEncryptOnG1(t *testing.T) {
	suite := bls.NewSuiteBLS12381()
	P := suite.G1().Point().Pick(random.New())
	s := suite.G1().Scalar().Pick(random.New())
	Ppub := suite.G1().Point().Mul(s, P)
	ID := []byte("passtherand")
	IDP := suite.G2().Point().(kyber.HashablePoint)
	Qid := IDP.Hash(ID)
	sQid := Qid.Mul(s, Qid)
	msg := []byte("Hello World\n")
	c, err := EncryptCPAonG1(suite, P, Ppub, ID, msg)
	require.NoError(t, err)
	msg2, err := DecryptCPAonG1(suite, sQid, c)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
}
*/
