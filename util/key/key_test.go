package key

import (
	"crypto/cipher"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
)

func TestNewKeyPair(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	keypair := NewKeyPair(suite, random.New())
	pub := suite.Point().Mul(keypair.Secret, nil)
	if !pub.Equal(keypair.Public) {
		t.Fatal("Public and private-key don't match")
	}
}

// A type to test interface Generator by intentionally creating a fixed private key.
type fixedPrivSuiteEd25519 edwards25519.SuiteEd25519

func (s *fixedPrivSuiteEd25519) NewKey(stream cipher.Stream) kyber.Scalar {
	return s.Scalar().SetInt64(33)
}

func TestNewKeyPairGen(t *testing.T) {
	suite := &fixedPrivSuiteEd25519{}
	key := NewKeyPair(suite, random.New())

	scalar33 := suite.Scalar().SetInt64(33)
	if !key.Secret.Equal(scalar33) {
		t.Fatalf("expected fixed private key, got %v", key.Secret)
	}
}
