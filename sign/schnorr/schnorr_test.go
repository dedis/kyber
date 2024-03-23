package schnorr

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSchnorrMalleability(t *testing.T) {
	/* l = 2^252+27742317777372353535851937790883648493, prime order of the base point */
	var L []uint16 = []uint16{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
		0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	var c uint16 = 0

	msg := []byte("Hello Schnorr")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	kp := key.NewKeyPair(suite)

	s, err := Sign(suite, kp.Private, msg)
	assert.NoErrorf(t, err, "Couldn't sign msg: %s: %v", msg, err)

	err = Verify(suite, kp.Public, msg, s)
	assert.NoErrorf(t, err, "Couldn't verify signature (schnorr.Verify): \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)

	// Add l to signature
	for i := 0; i < 32; i++ {
		c += uint16(s[32+i]) + L[i]
		s[32+i] = byte(c)
		c >>= 8
	}
	assert.Error(t, eddsa.Verify(kp.Public, msg, s))

	err = Verify(suite, kp.Public, msg, s)
	assert.Error(t, err, "schnorr signature malleable")
}

func FuzzSchnorr(f *testing.F) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	kp := key.NewKeyPair(suite)

	f.Fuzz(func(t *testing.T, msg []byte) {
		if (len(msg) < 1) || (len(msg) > 1000) {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		s, err := Sign(suite, kp.Private, msg)
		require.NoError(t, err, "Couldn't sign msg: %s: %v", msg, err)

		err = Verify(suite, kp.Public, msg, s)
		require.NoError(t, err, "Couldn't verify signature: \n%+v\nfor msg:'%s'. Error:\n%v", s, msg, err)
	})
}
