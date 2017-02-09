package sign

import (
	"testing"

	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
	"github.com/stretchr/testify/assert"
)

func TestSchnorrSignature(t *testing.T) {
	msg := []byte("Hello Schnorr")
	suite := ed25519.NewAES128SHA256Ed25519(false)
	kp := config.NewKeyPair(suite)

	s, err := Schnorr(suite, kp.Secret, msg)
	if err != nil {
		t.Fatalf("Couldn't sign msg: %s: %v", msg, err)
	}
	err = VerifySchnorr(suite, kp.Public, msg, s)
	if err != nil {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)
	}

	// wrong size
	larger := append(s, []byte{0x01, 0x02}...)
	assert.Error(t, VerifySchnorr(suite, kp.Public, msg, larger))

	// wrong challenge
	wrChall := make([]byte, len(s))
	copy(wrChall[:32], random.Bytes(32, random.Stream))
	copy(wrChall[32:], s[32:])
	assert.Error(t, VerifySchnorr(suite, kp.Public, msg, wrChall))

	// wrong response
	wrResp := make([]byte, len(s))
	copy(wrResp[:32], random.Bytes(32, random.Stream))
	copy(wrResp[32:], s[32:])
	assert.Error(t, VerifySchnorr(suite, kp.Public, msg, wrResp))

	// wrong public key
	wrKp := config.NewKeyPair(suite)
	assert.Error(t, VerifySchnorr(suite, wrKp.Public, msg, s))
}
