package sig

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"hash"
	"io"
)

// SchnorrScheme implements the classic Schnorr signature scheme,
// as originally proposed by Claus Peter Schnorr in
// "Efficient identification and signatures for smart cards",
// CRYPTO '89.
type SchnorrScheme struct {
	abstract.Suite          // Required: ciphersuite for signing scheme to use
	hidden         struct{} // keep it extensible
}

// XXX maybe Scheme isn't really needed if we're exposing
// the PublicKey/SecretKey types for each scheme?

// Create a public key object for Schnorr signatures.
func (s SchnorrScheme) PublicKey() PublicKey {
	return &SchnorrPublicKey{s, nil}
}

// Create a secret key object for Schnorr signatures.
func (s SchnorrScheme) SecretKey() SecretKey {
	return &SchnorrSecretKey{SchnorrPublicKey{s, nil}, nil}
}

///// Schnorr public keys

// SchnorrPublicKey represents a public key for verifying Schnorr signatures.
type SchnorrPublicKey struct {
	Suite abstract.Suite	// Crypto suite
	Point abstract.Point	// Curve point representing public key
}

func (k *SchnorrPublicKey) Init(suite abstract.Suite) *SchnorrPublicKey {
	k.Suite = suite
	return k
}

func (k *SchnorrPublicKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s", k.Point.String())
}

func (k *SchnorrPublicKey) Hash() hash.Hash {
	return k.Suite.Hash()
}

func (k *SchnorrPublicKey) SigSize() int {
	return k.Suite.SecretLen() * 2
}

func (k *SchnorrPublicKey) Verify(sig []byte, hash hash.Hash) error {
	suite := k.Suite

	// Decode the signature
	buf := bytes.NewBuffer(sig)
	var c, r abstract.Secret
	if err := suite.Read(buf, &c, &r); err != nil {
		return err
	}

	// Compute base**(r + x*c) == T
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(k.Point, c))

	// Update the hash to depend on the reconstructed point commitment
	_, err := T.MarshalTo(hash)
	if err != nil {
		return err
	}

	// Reconstruct the challenge from the hash
	hb := hash.Sum(nil)
	cc := suite.Secret().SetBytes(hb)

	// Verify that the reconstructed challenge matches the signature
	if !cc.Equal(c) {
		return errors.New("invalid signature")
	}

	return nil
}

func (k *SchnorrPublicKey) MarshalSize() int {
	return k.Point.MarshalSize()
}

func (k *SchnorrPublicKey) MarshalBinary() ([]byte, error) {
	return k.Point.MarshalBinary()
}

func (k *SchnorrPublicKey) MarshalTo(w io.Writer) (int, error) {
	return k.Point.MarshalTo(w)
}

func (k *SchnorrPublicKey) UnmarshalBinary(b []byte) error {
	return k.Point.UnmarshalBinary(b)
}

func (k *SchnorrPublicKey) UnmarshalFrom(r io.Reader) (int, error) {
	return k.Point.UnmarshalFrom(r)
}

///// Schnorr secret keys

// SchnorrSecretKey represents a secret key for generating Schnorr signatures.
type SchnorrSecretKey struct {
	SchnorrPublicKey
	Secret abstract.Secret	// Scalar representing secret key
}

func (k *SchnorrSecretKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s secret: %s",
		k.Point.String(), k.Secret.String())
}

func (k *SchnorrSecretKey) Pick(rand cipher.Stream) SecretKey {
	k.Secret = k.Suite.Secret().Pick(rand)
	k.Point = k.Suite.Point().Mul(nil, k.Secret)
	return k
}

func (k *SchnorrSecretKey) Sign(sig []byte, hash hash.Hash,
	rand cipher.Stream) ([]byte, error) {
	suite := k.Suite

	// Create random secret v and public point commitment T
	v := suite.Secret().Pick(rand)
	T := suite.Point().Mul(nil, v)

	// Update the hash to depend on the point commitment
	_, err := T.MarshalTo(hash)
	if err != nil {
		return nil, err
	}

	// Use the resulting hash to generate a Schnorr challenge
	hb := hash.Sum(nil)
	c := suite.Secret().SetBytes(hb)

	// Compute response r = v - x*c
	r := suite.Secret()
	r.Mul(k.Secret, c).Sub(v, r)

	// Produce verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	suite.Write(&buf, &c, &r)
	return append(sig, buf.Bytes()...), nil
}

func (k *SchnorrSecretKey) PublicKey() PublicKey {
	return &k.SchnorrPublicKey
}

func (k *SchnorrSecretKey) MarshalSize() int {
	return k.Secret.MarshalSize()
}

func (k *SchnorrSecretKey) MarshalBinary() ([]byte, error) {
	return k.Secret.MarshalBinary()
}

func (k *SchnorrSecretKey) MarshalTo(w io.Writer) (int, error) {
	return k.Secret.MarshalTo(w)
}

func (k *SchnorrSecretKey) UnmarshalBinary(b []byte) error {
	if k.Secret == nil {
		k.Secret = k.Suite.Secret()
	}
	if err := k.Secret.UnmarshalBinary(b); err != nil {
		return err
	}
	k.Point = k.Suite.Point().Mul(nil, k.Secret)
	return nil
}

func (k *SchnorrSecretKey) UnmarshalFrom(r io.Reader) (int, error) {
	if k.Secret == nil {
		k.Secret = k.Suite.Secret()
	}
	n, err := k.Secret.UnmarshalFrom(r)
	if err != nil {
		return n, err
	}
	k.Point = k.Suite.Point().Mul(nil, k.Secret)
	return n, nil
}
