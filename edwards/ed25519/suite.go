package ed25519

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

type suiteEd25519 struct {
	Curve
}

// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suiteEd25519) Cipher(key []byte, options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return abstract.SuiteRead(s, r, objs)
}

func (s *suiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return abstract.SuiteWrite(s, w, objs)
}

func (s *suiteEd25519) New(t reflect.Type) interface{} {
	return abstract.SuiteNew(s, t)
}

// NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
// it to be a multiple of 8)
func (s *suiteEd25519) NewKey(stream cipher.Stream) abstract.Secret {
	scalar, _ := NewEd25519Scalar(stream)
	nint := nist.NewInt(0, &primeOrder.V)
	nint.SetEndianness(binary.LittleEndian)
	nint.SetLittleEndian(scalar)
	return nint
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) abstract.Suite {
	suite := new(suiteEd25519)
	return suite
}

// NewEd25519Scalar returns the scalar derived from the stream and the right
// half of the hash during the derivation of the scalar.
func NewEd25519Scalar(stream cipher.Stream) ([]byte, []byte) {
	if stream == nil {
		stream = random.Stream
	}
	buffer := random.NonZeroBytes(32, stream)
	scalar := sha512.Sum512(buffer)
	scalar[0] &= 0xf8
	scalar[31] &= 0x3f
	scalar[31] |= 0x40
	return scalar[:32], scalar[32:]
}
