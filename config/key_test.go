package config_test

import (
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	suite := edwards.NewAES128SHA256Ed25519(false)
	priv, pub := config.NewKeyPair(suite)
	pub2 := suite.Point().Mul(nil, priv)
	if !pub.Equal(pub2) {
		t.Fatal("Public and private-key don't match")
	}
}
