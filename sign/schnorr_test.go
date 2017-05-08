package sign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/eddsa"
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
	wrongEncoding := []byte{243, 45, 180, 140, 73, 23, 41, 212, 250, 87, 157, 243,
		242, 19, 114, 161, 145, 47, 76, 26, 174, 150, 22, 177, 78, 79, 122, 30, 74,
		42, 156, 203}
	wrChall := make([]byte, len(s))
	copy(wrChall[:32], wrongEncoding)
	copy(wrChall[32:], s[32:])
	assert.Error(t, VerifySchnorr(suite, kp.Public, msg, wrChall))

	// wrong response
	wrResp := make([]byte, len(s))
	copy(wrResp[32:], wrongEncoding)
	copy(wrResp[:32], s[:32])
	assert.Error(t, VerifySchnorr(suite, kp.Public, msg, wrResp))

	// wrong public key
	wrKp := config.NewKeyPair(suite)
	assert.Error(t, VerifySchnorr(suite, wrKp.Public, msg, s))
}

func TestEdDSACompatibility(t *testing.T) {
	msg := []byte("Hello Schnorr")
	suite := ed25519.NewAES128SHA256Ed25519(false)
	kp := config.NewKeyPair(suite)

	s, err := Schnorr(suite, kp.Secret, msg)
	if err != nil {
		t.Fatalf("Couldn't sign msg: %s: %v", msg, err)
	}
	err = eddsa.Verify(kp.Public, msg, s)
	if err != nil {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)
	}

}
