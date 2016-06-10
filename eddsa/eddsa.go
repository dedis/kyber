package eddsa

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
)

var suite = ed25519.NewAES128SHA256Ed25519(false)

// EdDSA implements the EdDSA signature algorithm according to
// the RFC https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
type EdDSA struct {
	seed   []byte
	prefix []byte
	// Secret being already hashed + bit tweaked
	Secret abstract.Secret
	// Public is the corresponding public key
	Public abstract.Point
}

// NewEdDSAKey will return a freshly generated key pair to use for generating
// EdDSA signatures.
// If stream == nil, it will take the random.Stream.
func NewEdDSA(stream cipher.Stream) *EdDSA {
	if stream == nil {
		stream = random.Stream
	}
	buffer := random.NonZeroBytes(32, stream)

	scalar := sha512.Sum512(buffer)
	scalar[0] &= 0xf8
	scalar[31] &= 0x3f
	scalar[31] |= 0x40

	secret := suite.Secret().SetBytes(scalar[:32])
	public := suite.Point().Mul(nil, secret)

	return &EdDSA{
		seed:   buffer,
		prefix: scalar[32:],
		Secret: secret,
		Public: public,
	}
}

// Prefix returns the Prefix as being the right part of
// the hashed seed
func (e *EdDSA) Prefix() []byte {
	c := make([]byte, len(e.prefix))
	copy(c, e.prefix)
	return c
}

// MarshalBinary will return the representation used by
// the reference implementation of SUPERCOP ref10
// Namely seed || Public
func (e *EdDSA) MarshalBinary() ([]byte, error) {
	pBuff, err := e.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	eddsa := make([]byte, 64)
	copy(eddsa, e.seed)
	copy(eddsa[32:], pBuff)
	return eddsa, nil
}

func (e *EdDSA) UnmarshalBinary(buff []byte) error {
	if len(buff) != 64 {
		return errors.New("Wrong length for decoding EdDSA private")
	}

	e.seed = buff[:32]
	e.prefix = buff[32:64]
	e.Secret = suite.Secret().SetBytes(e.seed)
	e.Public = suite.Point().Mul(nil, e.Secret)
	return nil
}

// Sign will return a EdDSA signature of the message msg using Ed25519.
// NOTE: Code taken from the Python implementation from the RFC
// https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
func (e *EdDSA) Sign(msg []byte) ([]byte, error) {
	hash := sha512.New()
	hash.Write(e.prefix)
	hash.Write(msg)

	// deterministic random secret and its commit
	r := suite.Secret().SetBytes(hash.Sum(nil))
	R := suite.Point().Mul(nil, r)

	// challenge
	// H( R || Public || Msg)
	hash.Reset()
	Rbuff, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	Abuff, err := e.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash.Write(Rbuff)
	hash.Write(Abuff)
	hash.Write(msg)

	h := suite.Secret().SetBytes(hash.Sum(nil))

	// response
	// s = r  h * secret
	s := suite.Secret().Mul(e.Secret, h)
	s.Add(r, s)

	sBuff, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// return R || s
	var sig [64]byte
	copy(sig[:], Rbuff)
	copy(sig[32:], sBuff)

	return sig[:], nil
}

// Verify verify a signature issued by EdDSA.Sign
// Takes:
//  - public key used in signing
//  - msg is the message to sign
//  - sig is the signature return by EdDSA.Sign
// Returns an error on failure and nil on success
func Verify(public abstract.Point, msg, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("Signature length invalid")
	}

	R := suite.Point()
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("R invalid point: %s", err)
	}

	s := suite.Secret()
	s.UnmarshalBinary(sig[32:])

	// reconstruct h = H(R || Public || Msg)
	Pbuff, err := public.MarshalBinary()
	if err != nil {
		return err
	}
	hash := sha512.New()
	hash.Write(sig[:32])
	hash.Write(Pbuff)
	hash.Write(msg)

	h := suite.Secret().SetBytes(hash.Sum(nil))
	// reconstruct S == k*A  R
	S := suite.Point().Mul(nil, s)
	hA := suite.Point().Mul(public, h)
	RhA := suite.Point().Add(R, hA)

	if !RhA.Equal(S) {
		return errors.New("Recontructed S is not equal to signature")
	}
	return nil
}
