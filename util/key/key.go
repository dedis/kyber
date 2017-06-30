// Package key provide a wrapper to handle conveniently an asymmetric key pair.
package key

import (
	"crypto/cipher"
	"encoding/base64"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/util/random"
)

// Suite represents the list of functionalities needed by this package.
// XXX HashFactory might be removed in the future, it's only needed to generate
// the PubId.
type Suite interface {
	kyber.Group
	kyber.HashFactory
}

// Pair represents a public/private keypair
// together with the ciphersuite the key was generated from.
type Pair struct {
	Suite  Suite        // Ciphersuite this keypair is for
	Public kyber.Point  // Public key
	Secret kyber.Scalar // Secret key
}

// NewKeyPair directly creates a secret/public key pair
func NewKeyPair(suite Suite) *Pair {
	kp := new(Pair)
	kp.Gen(suite, random.Stream)
	return kp
}

// Gen creates a fresh public/private keypair with the given ciphersuite,
// using a given source of cryptographic randomness.
func (p *Pair) Gen(suite Suite, random cipher.Stream) {
	p.Suite = suite
	p.Secret = suite.NewKey(random)
	p.Public = suite.Point().Mul(p.Secret, nil)
}

// PubID returns the base64-encoded HashId for this Pair's public key.
func (p *Pair) PubID() string {
	buf, _ := p.Public.MarshalBinary()
	hash := p.Suite.Hash()
	_, _ = hash.Write(buf)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
