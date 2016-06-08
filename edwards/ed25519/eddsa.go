package ed25519

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/util"
)

type EdDSA struct {
	Secret abstract.Secret
	prefix []byte
	Public abstract.Point
}

func NewEdDSA(randStream cipher.Stream) *EdDSA {
	// XXX if this PR is accepted, then change this line to iterate as long as
	// we have 0x00...00 slice buffer. See issue #70
	randSlice := random.Bytes(32, randStream)
	hash := sha512.New()
	hash.Write(randSlice)
	// XXX Should we copy it to s and prefix ?
	expanded := hash.Sum(nil)
	s := expanded[0:32]
	prefix := expanded[32:]
	s[0] &= 0xf8
	s[31] &= 0x7f
	s[31] |= 0x40
	// giving the reverse as nist.Int expect big endian
	var reverse [32]byte
	util.Reverse(reverse[:], s)
	suite := NewAES128SHA256Ed25519(false)
	// We can't use Secret().Pick() because it uses random.int which tests if
	// the results is < Mod, which is never true (because of the bit tweaks)
	sec := suite.Secret().(*nist.Int)
	sec.SetLittleEndian(s)
	pub := suite.Point().Mul(nil, sec)
	return &EdDSA{
		Secret: sec,
		Public: pub,
		prefix: prefix,
	}
}

func (ed *EdDSA) Sign(msg []byte) ([]byte, error) {
	sec := ed.Secret
	hash := sha512.New()
	hash.Write(ed.prefix)
	hash.Write(msg)

	suite := NewAES128SHA256Ed25519(false)

	// deterministic random secret and its commit
	r := suite.Secret().(*nist.Int)
	r.SetLittleEndian(hash.Sum(nil))
	R := suite.Point().Mul(nil, r)

	// challenge
	// H( R || Public || Msg)
	hash.Reset()
	Rbuff, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	Abuff, err := ed.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash.Write(Rbuff)
	hash.Write(Abuff)
	hash.Write(msg)

	h := suite.Secret().(*nist.Int)
	h.SetLittleEndian(hash.Sum(nil))

	// response
	// s = r  h * secret
	s := suite.Secret().Mul(sec, h)
	s.Add(r, s)

	sBuff, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// have to put s as a little endian
	sBuffLE := make([]byte, 32)
	util.Reverse(sBuffLE, sBuff)

	// return R || s
	var sig [64]byte
	copy(sig[:], Rbuff)
	copy(sig[32:], sBuffLE)

	return sig[:], nil
}

// EdDSAVerify verifies a signature issued by EdDSASign
// Takes:
//  - public key used in signing
//  - msg is the message to sign
//  - sig is the signature return by EdDSASign
// Returns an error on failure and nil on success
func EdDSAVerify(public abstract.Point, msg, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("Signature length invalid")
	}

	suite := NewAES128SHA256Ed25519(false)
	R := suite.Point()
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("R invalid point: %s", err)
	}

	s := suite.Secret()
	sBuffLE := make([]byte, 32)
	util.Reverse(sBuffLE, sig[32:])
	s.UnmarshalBinary(sBuffLE)

	// reconstruct h = H(R || Public || Msg)
	Pbuff, err := public.MarshalBinary()
	if err != nil {
		return err
	}
	hash := sha512.New()
	hash.Write(sig[:32])
	hash.Write(Pbuff)
	hash.Write(msg)

	h := suite.Secret().(*nist.Int)
	h.SetLittleEndian(hash.Sum(nil))
	// reconstruct S == k*A  R
	S := suite.Point().Mul(nil, s)
	hA := suite.Point().Mul(public, h)
	RhA := suite.Point().Add(R, hA)

	if !RhA.Equal(S) {
		return errors.New("Recontructed S is not equal to signature")
	}
	return nil
}

type fixedStream struct {
	seed []byte
}

func (f *fixedStream) XORKeyStream(dst, src []byte) {
	copy(dst, f.seed)
}
