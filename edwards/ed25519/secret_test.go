package ed25519

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/stretchr/testify/assert"
)

var suite = NewAES128SHA256Ed25519(false)

func randomSecret() abstract.Secret {
	return suite.Secret().Pick(random.Stream)
}

func TestSecretEqual(t *testing.T) {
	s1 := randomSecret()
	s2 := suite.Secret().Set(s1)

	if !s1.Equal(s2) || !s2.Equal(s1) {
		t.Error("Ed25519 secrets not equal")
	}
}

func TestSecretAddSub(t *testing.T) {
	s := randomSecret()
	s1 := suite.Secret().One()
	add1 := suite.Secret().Add(s, s1)
	sub1 := suite.Secret().Sub(add1, s1)
	if !sub1.Equal(s) {
		t.Error("Add / Sub does not work")
	}
}

func TestSecretMarshal(t *testing.T) {
	s := randomSecret()
	buff, err := s.MarshalBinary()
	assert.Nil(t, err)

	s2 := suite.Secret()
	assert.Nil(t, s2.UnmarshalBinary(buff))

	if !s.Equal(s2) {
		t.Error("Secret marshaling does not work")
	}
}
