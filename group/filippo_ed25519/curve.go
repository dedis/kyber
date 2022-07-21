package filippo_ed25519

import (
	"crypto/cipher"
	"crypto/sha512"
	filippo_ed25519 "filippo.io/edwards25519"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

// Curve represents the Ed25519 group.
// There are no parameters and no initialization is required
// because it supports only this one specific curve.
type Curve struct {
}

// Return the name of the curve, "Ed25519".
func (c *Curve) String() string {
	return "Ed25519"
}

// ScalarLen returns 32, the size in bytes of an encoded Scalar
// for the Ed25519 curve.
func (c *Curve) ScalarLen() int {
	return 32
}

// Scalar creates a new Scalar for the prime-order subgroup of the Ed25519 curve.
// The scalars in this package implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a little-endian integer, in order to remain
// compatible with other Ed25519 implementations, and with the standard implementation
// of the EdDSA signature.
func (c *Curve) Scalar() kyber.Scalar {
	return &Scalar{new(filippo_ed25519.Scalar)}
}

// PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
func (c *Curve) PointLen() int {
	return 32
}

// Point creates a new Point on the Ed25519 curve.
func (c *Curve) Point() kyber.Point {
	P := Point{new(filippo_ed25519.Point)}
	return &P
}

// NewKeyAndSeedWithInput returns a formatted Ed25519 key (avoid subgroup attack by
// requiring it to be a multiple of 8). It also returns the input and the digest used
// to generate the key.
func (c *Curve) NewKeyAndSeedWithInput(buffer []byte) (kyber.Scalar, []byte, []byte) {
	digest := sha512.Sum512(buffer[:])
	digest[0] &= 0xf8
	digest[31] &= 0xf

	// In here the 31st byte has been done AND 16 just to bring the secret key chosen below the group order i.e. l
	// in which the highest priority byte is 16. Doing the normal procedure of unsetting the highest priority bit and
	// setting the highest priority bit leads to errors when the secret is passed to the filippo library which expects
	// all the scalars to be below l.

	secret := c.Scalar().(*Scalar)
	secret.SetBytes(digest[:32])
	return secret, buffer, digest[32:]
}

// NewKeyAndSeed returns a formatted Ed25519 key (avoid subgroup attack by requiring
// it to be a multiple of 8). It also returns the seed and the input used to generate
// the key.
func (c *Curve) NewKeyAndSeed(stream cipher.Stream) (kyber.Scalar, []byte, []byte) {
	var buffer [32]byte
	random.Bytes(buffer[:], stream)
	return c.NewKeyAndSeedWithInput(buffer[:])
}

// NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
// it to be a multiple of 8). NewKey implements the kyber/util/key.Generator interface.
func (c *Curve) NewKey(stream cipher.Stream) kyber.Scalar {
	secret, _, _ := c.NewKeyAndSeed(stream)
	return secret
}
