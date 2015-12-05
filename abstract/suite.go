package abstract

import (
	"github.com/dedis/crypto/cipher"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/marshal"
	"golang.org/x/net/context"
	"io"
)

// Context is an alias of the standard context.Context interface,
// which we use to pass cryptographic cipher suite configuration context
// such as specific symmetric ciphers and public-key groups to use.
//
// XXX this type alias isn't as useful as I thought it would be;
// we could probably do without it.
type Context context.Context

// Suite provides a convenient front-end convenience class for accessing
// the public-key and symmetric-key ciphersuites configured in a context.
type Suite struct {
	*suiteCache
}

// Cache of important ciphersuite information from a Context
type suiteCache struct {
	ctx    context.Context
	group  group.Group  // cached public-key cipher suite
	cipher cipher.Suite // cached symmetric-key cipher suite
}

// Get a Suite object to provide access to the ciphersuite in given context.
func GetSuite(ctx context.Context) Suite {
	cache := &suiteCache{ctx, group.Get(ctx), cipher.Get(ctx)}
	return Suite{cache}
}

// Return the context this Suite was created from.
func (s Suite) Context() context.Context {
	return s.ctx
}

// Return the configured cryptographic group for public-key crypto.
func (s Suite) Group() group.Group {
	return s.group
}

// Create a new Point instance from the configured cryptographic group.
func (s Suite) Point() Point {
	return Point{s.group.Element()}
}

// Return the encoded length of Point objects in the configured group.
func (s Suite) PointLen() int {
	return s.group.ElementLen()
}

// Create a new Scalar modulo the order of the configured cryptographic group.
func (s Suite) Scalar() Scalar {
	return Scalar{s.group.Scalar()}
}

// Return the encoded length of Scalar objects in the configured group.
func (s Suite) ScalarLen() int {
	return s.group.ScalarLen()
}

// Return the configured symmetric-key ciphersuite.
func (s Suite) CipherSuite() cipher.Suite {
	return s.cipher
}

// Create a new general message Cipher instance with a given key,
// which may be NoKey for an unkeyed cipher
// or FreshKey to use a fresh random key.
func (s Suite) Cipher(key []byte) Cipher {
	return Cipher{s.cipher.Cipher(key)}
}

// Create a new Hash with a given optional key,
// which may be NoKey for an unkeyed cipher
// or FreshKey to use a fresh random key.
func (s Suite) Hash(key []byte) cipher.Hash {
	if hashsuite, ok := s.cipher.(cipher.Hasher); ok {
		return hashsuite.Hash(key)
	}
	return cipher.NewCipherHash(s.cipher.Cipher(key))
}

// Create a new Stream cipher with a given optional key,
// which may be NoKey for an unkeyed cipher
// or FreshKey to use a fresh random key.
func (s Suite) Stream(key []byte) cipher.Stream {
	if streamsuite, ok := s.cipher.(cipher.Streamer); ok {
		return streamsuite.Stream(key)
	}
	return Cipher{s.cipher.Cipher(key)}
}

// Write data structures containing cryptographic objects and regular types,
// using the rigid binary encoding defined in the marshal package.
func (s Suite) Write(w io.Writer, objs ...interface{}) error {
	return marshal.Write(s.ctx, w, objs...)
}

// Read data structures containing cryptographic objects and regular types,
// using the rigid binary encoding defined in the marshal package.
func (s Suite) Read(r io.Reader, objs ...interface{}) error {
	return marshal.Read(s.ctx, r, objs...)
}

// Sum uses this ciphersuite's hash function to checksum a byte-slice.
func (s Suite) Sum(data []byte) []byte {
	h := s.Hash(cipher.NoKey)
	h.Write(data)
	return h.Sum(nil)
}

// Pass NoKey to a symmetric cipher constructor to create an unkeyed cipher.
var NoKey = cipher.NoKey

// Pass FreshKey to a cipher constructor to create a freshly seeded cipher.
var FreshKey = cipher.FreshKey

