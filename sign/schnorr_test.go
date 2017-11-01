package sign

import (
	"encoding/hex"
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

func TestSchnorrSignature2(t *testing.T) {
	suite := ed25519.NewAES128SHA256Ed25519(false)
	msg := []byte("Hello Schnorr")
	sigStr := "b95fc52a5fd2e18aa7ace5b2250c2a25e368f75c148ea3403c8f32b5f100781b" +
		"362c668aab4cf50eafdc2fcf45214c0dfbe86fce72e4632158c02c571e977306"
	sig, _ := hex.DecodeString(sigStr)
	pubStr := "59d7fd947fc88e47d3f878e82e26629dea7a28e8d4233f11068a6b464e195bfd"
	pubBuf, _ := hex.DecodeString(pubStr)
	pub := suite.Point()
	pub.UnmarshalBinary(pubBuf)

	if err := VerifySchnorr(suite, pub, msg, sig); err != nil {
		t.Fatalf("Wrong schnorr signature: %s", err)
	}
	t.Log("Successfully verified schnorr signature")
}
