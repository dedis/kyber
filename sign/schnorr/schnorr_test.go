package schnorr

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/eddsa"
	"go.dedis.ch/kyber/v3/util/key"
)

func TestSchnorrSignature(t *testing.T) {
	msg := []byte("Hello Schnorr")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	kp := key.NewKeyPair(suite)

	s, err := Sign(suite, kp.Private, msg)
	if err != nil {
		t.Fatalf("Couldn't sign msg: %s: %v", msg, err)
	}
	err = Verify(suite, kp.Public, msg, s)
	if err != nil {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)
	}

	// wrong size
	larger := append(s, []byte{0x01, 0x02}...)
	assert.Error(t, Verify(suite, kp.Public, msg, larger))

	// wrong challenge
	wrongEncoding := []byte{243, 45, 180, 140, 73, 23, 41, 212, 250, 87, 157, 243,
		242, 19, 114, 161, 145, 47, 76, 26, 174, 150, 22, 177, 78, 79, 122, 30, 74,
		42, 156, 203}
	wrChall := make([]byte, len(s))
	copy(wrChall[:32], wrongEncoding)
	copy(wrChall[32:], s[32:])
	assert.Error(t, Verify(suite, kp.Public, msg, wrChall))

	// wrong response
	wrResp := make([]byte, len(s))
	copy(wrResp[32:], wrongEncoding)
	copy(wrResp[:32], s[:32])
	assert.Error(t, Verify(suite, kp.Public, msg, wrResp))

	// wrong public key
	wrKp := key.NewKeyPair(suite)
	assert.Error(t, Verify(suite, wrKp.Public, msg, s))
}

func TestEdDSACompatibility(t *testing.T) {
	msg := []byte("Hello Schnorr")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	kp := key.NewKeyPair(suite)

	s, err := Sign(suite, kp.Private, msg)
	if err != nil {
		t.Fatalf("Couldn't sign msg: %s: %v", msg, err)
	}
	err = eddsa.Verify(kp.Public, msg, s)
	if err != nil {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)
	}

}

// Simple random stream using the random instance provided by the testing tool
type quickstream struct {
	rand *rand.Rand
}

func (s *quickstream) XORKeyStream(dst, src []byte) {
	s.rand.Read(dst)
}

func (s *quickstream) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(&quickstream{rand: rand})
}

func TestQuickSchnorrSignature(t *testing.T) {
	f := func(rand *quickstream, msg []byte) bool {
		suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
		kp := key.NewKeyPair(suite)

		s, err := Sign(suite, kp.Private, msg)
		if err != nil {
			return false
		}

		return Verify(suite, kp.Public, msg, s) == nil
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Schnorr is only defined for scalars which are not the additive identity
// because if it was allowed, then the math works out such that the message
// hash is ignored, and the same signature would verify for any message
// for the public key which is the neutral identity point. The following
// two tests check the errors we added to protect callers from this mistake.

func TestBadPubKey(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// This is a good signature made on msg with private
	// key Scalar().Zero() before that input was made into
	// an error in Sign.
	msg := []byte("Hello Schnorr")
	sig := []byte{0xf4, 0x8a, 0x95, 0x90, 0xf7, 0xcc, 0x4d, 0x7b, 0xc3, 0xd3, 0x88, 0x64, 0x0, 0xd5, 0xf2, 0x9a, 0x3c, 0xde, 0x60, 0xd9, 0xe5, 0xb2, 0x4d, 0x68, 0x4c, 0x23, 0x7d, 0x6, 0x7c, 0x3, 0xcf, 0x0, 0x2c, 0xe, 0x17, 0xbf, 0xb, 0x9b, 0xa1, 0x2b, 0xa2, 0x10, 0xae, 0x59, 0x3d, 0xd, 0x34, 0xa9, 0x10, 0x31, 0x58, 0x9, 0x92, 0x40, 0x50, 0x68, 0x5a, 0x7c, 0xe7, 0x62, 0x32, 0xc7, 0xa5, 0x8}

	// Modifying one byte of the message would still allow
	// the signature to verify because the public key is Null.
	msg[0]++

	pn := suite.Point().Null()
	err := Verify(suite, pn, msg, sig)

	// Before the check, err was nil here, a dangerous situation where a
	// signature still verifies against a modified message. With the check, the
	// error is about the invalid public key.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}
