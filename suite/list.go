// This package contains convenience functions to configure ciphersuites,
// defined elsewhere in other packages.
package suite

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/nist"
	"golang.org/x/net/context"
	"fmt"
)

func ctx(parent abstract.Context) abstract.Context {
	return parent
}

type withFunc func(abstract.Context) abstract.Context

func suite(ctx abstract.Context, pub, sym withFunc) abstract.Suite {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = pub(ctx)                // Configure public-key group
	ctx = sym(ctx)                // Configure symmetric-key cipher
	return abstract.GetSuite(ctx) // Turn it into a Suite object
}

// Create a NIST-based suite with 128-bit security,
// using the P-256 curve and the SHAKE128 sponge cipher.
func Nist128(parent abstract.Context) abstract.Suite {
	return suite(parent, nist.WithP256, sha3.WithShake128)
}

// XXX add 384-bit and 512-bit NIST-based suites.

// Create a context configured to use the Ed25519 curve
// and the SHAKE158 sponge cipher.
// XXX change to use BLAKE2 instead of SHAKE
func Ed128(parent abstract.Context) abstract.Suite {
	return suite(parent, ed25519.WithEd25519, sha3.WithShake128)
}

// Create a Suite configured with some default ciphersuite,
// mainly for testing and development purposes.
// Which particular ciphersuite this corresponds to may change at any time.
func Default(parent abstract.Context) abstract.Suite {
	return Ed128(parent)
}

// A Config function configures a ciphersuite derived from a given context.
// In blatant defiance of stick-up-the-ass Google policy,
// the Config functions defined here accept nil as a synonym for
// context.Background().
//
type Config func(parent abstract.Context) abstract.Suite

func All() map[string]Config {
	return map[string]Config{
		"nist128":        Nist128,
		"ed128":          Ed128,
	}
}

// Named returns the Config named by a string if any, or else an error.
func Named(s string) (Config, error) {
	suite, ok := All()[s]
	if !ok {
		return nil, fmt.Errorf("No suite named %s", s)
	}
	return suite, nil
}

// XXX add Stable() and Experimental() sub-lists?
