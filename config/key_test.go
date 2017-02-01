package config_test

import (
	"testing"

	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
)

func TestNewKeyPair(t *testing.T) {
	suite := edwards.NewAES128SHA256Ed25519(false)
	keypair := config.NewKeyPair(suite)
	pub := suite.Point().Mul(nil, keypair.Secret)
	if !pub.Equal(keypair.Public) {
		t.Fatal("Public and private-key don't match")
	}
}
