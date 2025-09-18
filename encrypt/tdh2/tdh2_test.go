package tdh2

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/group/p256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/util/random"
)

func TestThresholdDecryption(t *testing.T) {
	// using Ed25519 curve group for elliptic curve operations
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create a public/private keypair
	private := suite.Scalar().Pick(suite.RandomStream()) // private key
	public := suite.Point().Mul(private, nil)            // public key

	// ElGamal-encrypt a message using the public key.
	m := []byte("This is the 24-bytes key")
	label := []byte("some random label")
	useAESGCM := true
	ct, err := Encrypt(suite, public, m, label, useAESGCM)
	require.NoError(t, err, "encryption failed")

	// verify ct
	err = Verify(suite, ct, public, label)
	require.NoError(t, err)

	// verify with wrong public key
	wrongPrivate := suite.Scalar().Pick(suite.RandomStream()) // private key
	wrongPublic := suite.Point().Mul(wrongPrivate, nil)
	err = Verify(suite, ct, wrongPublic, label)
	require.Error(t, err, "verification with wrong public key should fail")

	// verify with wrong label
	wrongLabel := []byte("wrong label")
	err = Verify(suite, ct, public, wrongLabel)
	require.Error(t, err, "verification with wrong label key should fail")

	// Threshold ElGamal
	n := 5         // total shares
	threshold := 2 // threshold

	privPoly := share.NewPriPoly(suite, threshold, private, random.New())
	shares := privPoly.Shares(n)

	publicKeys := make([]kyber.Point, len(shares))
	for i := 0; i < len(shares); i++ {
		// q_i = x_i * G
		publicKeys[i] = suite.Point().Mul(shares[i].V, nil)
	}
	// Simulate partial decryptions (using 3 shares)
	partials := make([]*PartialDecryptionShare, threshold+1)
	for i := 0; i <= threshold; i++ {
		partials[i], err = PartialDecrypt(suite, ct, shares[i].I, shares[i].V, label, public)
		require.NoError(t, err, "partial decryption failed")

		err := VerifyPartialDecryptionShare(suite, ct, partials[i], publicKeys[shares[i].I], public)
		require.NoError(t, err, "partial decryption verification failed")

		// wrong public key
		err = VerifyPartialDecryptionShare(suite, ct, partials[i], public, public)
		require.Error(t, err, "partial decryption verification should failed")
	}

	// Combine partial decryptions
	combined, validPartials, err := CombinePartialDecryptionShares(suite, ct, partials, publicKeys, threshold, label, public, useAESGCM)
	require.NoError(t, err, "combining shares failed")
	require.Equal(t, len(partials), validPartials, "wrong number of valid partial decryptions")

	// check that the decrypted message matches the original
	require.Equal(t, string(combined), string(m), "decryption produced wrong output")
}

func TestXORBytes(t *testing.T) {
	a := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	b := []byte{0x05, 0x06, 0x07, 0x08, 0x09}
	expected := []byte{0x05, 0x07, 0x05, 0x0b, 0x0d}

	result, err := xorByteSlices(a, b)
	require.NoError(t, err, "xorBytes failed")
	require.Equal(t, expected, result, "xorBytes produced wrong output")

	// test with different lengths
	a = []byte{0x00, 0x01, 0x02}
	b = []byte{0x05, 0x06, 0x07, 0x08}

	_, err = xorByteSlices(a, b)
	require.Error(t, err, "xorBytes failed")
}

func TestValidatePoint(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	p1 := suite.Point().Null()
	require.NoError(t, validatePoint(suite, p1), "valid point marked as invalid")

	p2 := suite.Point().Pick(random.New())
	require.NoError(t, validatePoint(suite, p2), "valid point marked as invalid")

	// zero point
	anotherSuite := p256.NewBlakeSHA256P256()
	pp := anotherSuite.Point().Null()
	require.Error(t, validatePoint(suite, pp), "zero point marked as valid")
}
