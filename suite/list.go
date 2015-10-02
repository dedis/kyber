// This package contains convenience functions to configure ciphersuites,
// defined elsewhere in other packages.
package suite

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/nist"
	"golang.org/x/net/context"
)

func ctx(parent abstract.Context) abstract.Context {
	if parent == nil {
		parent = context.Background()
	}
	return parent
}

// Create a context configured for a NIST-based suite with 128-bit security,
// using the P-256 curve and the SHAKE128 sponge cipher.
func WithNist128(parent abstract.Context) abstract.Context {
	return nist.WithP256(sha3.WithShake128(ctx(parent)))
}

// XXX add 384-bit and 512-bit NIST-based suites.

// Create a context configured to use the Ed25519 curve
// and the SHAKE158 sponge cipher.
// XXX change to use BLAKE2 instead of SHAKE
func WithEd128(parent abstract.Context) abstract.Context {
	return ed25519.WithEd25519(sha3.WithShake128(ctx(parent)))
}

// Create a context configured with some default ciphersuite,
// mainly for testing and development purposes.
// Which particular ciphersuite this corresponds to may change at any time.
func WithDefault(parent abstract.Context) abstract.Context {
	return WithEd128(parent)
}

// Return an abstract.Suite configured with a default ciphersuite.
func Default(parent abstract.Context) *abstract.Suite {
	return abstract.NewSuite(WithDefault(nil))
}

// A Suite is represented by a With function
// that configures a derived context appropriately.
//
// In blatant defiance of stick-up-the-ass Google policy,
// the With functions define here accept nil as a synonym for
// context.Background().
//
// XXX too much overloading of the name Suite, probably
type Suite func(parent abstract.Context) abstract.Context

// Suites represents a map from ciphersuite name to ciphersuite.
type Suites map[string]Suite

func All() Suites {
	s := make(Suites)
	s["nist128"] = WithNist128
	s["ed128"] = WithEd128
	return s
}

// XXX add Stable() and Experimental() sub-lists?
