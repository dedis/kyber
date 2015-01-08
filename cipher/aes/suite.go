package aes

import (
	"hash"
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
	"github.com/dedis/crypto/cipher/generic"
)

type suite128 struct{}

// SHA256 hash function
func (s *suite128) HashLen() int { return sha256.Size }
func (s *suite128) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suite128) KeyLen() int { return 16 }
func (s *suite128) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// SHA3/SHAKE128 sponge
func (s *suite128) Sponge() abstract.Sponge {
	return sha3.NewSponge128()
}

// Instantiate a ciphersuite based on AES-128, SHA-256,
// and the NIST P-256 elliptic curve.
func Suite128() abstract.Suite {
	suite := new(suite128)
	suite.p256.Init()
	return suite
}

func newSha(keylen int) Hash {
	switch keylen {
	case 128/8:		return sha256.New()
	case 192/8:		return sha512.New384()
	case 256/8:		return sha512.New()
	default:		panic("bad keylen")
	}
}

func new(keylen int, t reflect.Type) interface{} {
	switch t {
	case cipher.StateType:	return s.State(nil)
	case cipher.HashType:	return s.Hash()
	default:		return nil	// unknown interface type
	}
}

func (s *suite128) New(t reflect.Type) interface{} {
	return new(s.keylen, t)
}

func (s *suite128) KeyLen() int {
	return 128/8
}

func (s *suite128) HashLen() int {
	return 128*2/8
}

func (s *suite128) Hash() hash.Hash {
	return sha256.New()
}

func (s *suite128) State(key ...interface{}) State {
	st := &state128{}
	if len(key) > 0 {
		h := sha256.New()
		generic.HashAbsorb(h, key)
		copy(st.h[:], h.Sum(nil))
	}
	return &st
}

func (s *suite128) Read(r io.Reader, obj ...interface{}) error {
	return generic.Read(s, r, obj...)
}

func (s *suite128) Write(w io.Writer, obj ...interface{}) error {
	return generic.Write(s, w, obj...)
}

func (s *suite128) Erase(obj ...interface{}) {
	return generic.Erase(obj...)
}


// Instantiate an AES-based ciphersuite with a given key length in bytes,
// which must be 128, 192, or 256.
func Suite(keylen int) cipher.Suite {
	switch keylen {
	case 128/8:	return suite{keylen}
	default:	panic("Unsupported AES key length")
	}
}

