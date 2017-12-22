package key

import (
	"crypto/cipher"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
)

func TestNewKeyPair(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	keypair := NewKeyPair(suite)
	pub := suite.Point().Mul(keypair.Private, nil)
	if !pub.Equal(keypair.Public) {
		t.Fatal("Public and private keys don't match")
	}
	t.Log(pub)
}

// A type to test interface Generator by intentionally creating a fixed private key.
type fixedPrivSuiteEd25519 edwards25519.SuiteEd25519

func (s *fixedPrivSuiteEd25519) NewKey(stream cipher.Stream) kyber.Scalar {
	return s.Scalar().SetInt64(33)
}

// This is never called anyway, so it doesn't matter what it returns.
func (s *fixedPrivSuiteEd25519) RandomStream() cipher.Stream { return nil }

func TestNewKeyPairGen(t *testing.T) {
	suite := &fixedPrivSuiteEd25519{}
	key := NewKeyPair(suite)

	scalar33 := suite.Scalar().SetInt64(33)
	if !key.Private.Equal(scalar33) {
		t.Fatalf("expected fixed private key, got %v", key.Private)
	}
}
