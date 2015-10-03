package sig

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"golang.org/x/net/context"
	"hash"
	"io"
)

// SchnorrScheme implements the classic Schnorr signature scheme,
// as originally proposed by Claus Peter Schnorr in
// "Efficient identification and signatures for smart cards",
// CRYPTO '89.
type SchnorrScheme struct {
	Suite *abstract.Suite          // Ciphersuite to use
}

// XXX maybe Scheme isn't really needed if we're exposing
// the PublicKey/SecretKey types for each scheme?

func (s SchnorrScheme) Context() context.Context {
	return s.Suite.Context()
}

// Create a public key object for Schnorr signatures.
func (s SchnorrScheme) PublicKey() PublicKey {
	return new(SchnorrPublicKey).Init(s.Suite)
}

// Create a secret key object for Schnorr signatures.
func (s SchnorrScheme) SecretKey() SecretKey {
	return new(SchnorrSecretKey).Init(s.Suite)
}

///// Schnorr public keys

// SchnorrPublicKey represents a public key for verifying Schnorr signatures.
type SchnorrPublicKey struct {
	Suite *abstract.Suite // Crypto suite
	Point abstract.Point  // Curve point representing public key
}

func (k *SchnorrPublicKey) Init(suite *abstract.Suite) *SchnorrPublicKey {
	k.Suite = suite
	return k
}

func (k *SchnorrPublicKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s", k.Point.String())
}

func (k *SchnorrPublicKey) Hash() hash.Hash {
	return k.Suite.Hash(abstract.NoKey)
}

func (k *SchnorrPublicKey) SigSize() int {
	return k.Suite.ScalarLen() * 2
}

func (k *SchnorrPublicKey) Verify(sig []byte, hash hash.Hash) error {
	suite := k.Suite

	// Decode the signature
	buf := bytes.NewBuffer(sig)
	var c, r abstract.Scalar
	if err := suite.Read(buf, &c, &r); err != nil {
		return err
	}

	// Compute base**(r + x*c) == T
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.BaseMul(r), P.Mul(k.Point, c))

	// Update the hash to depend on the reconstructed point commitment
	_, err := T.Marshal(suite.Context(), hash)
	if err != nil {
		return err
	}

	// Reconstruct the challenge from the hash
	hb := hash.Sum(nil)
	cc := suite.Scalar().Random(random.ByteStream(hb))

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

func (k *SchnorrPublicKey) Marshal(ctx context.Context, w io.Writer) (int, error) {
	return k.Point.Marshal(ctx, w)
}

func (k *SchnorrPublicKey) UnmarshalBinary(b []byte) error {
	return k.Point.UnmarshalBinary(b)
}

func (k *SchnorrPublicKey) Unmarshal(ctx context.Context, r io.Reader) (int, error) {
	return k.Point.Unmarshal(ctx, r)
}

///// Schnorr secret keys

// SchnorrSecretKey represents a secret key for generating Schnorr signatures.
type SchnorrSecretKey struct {
	SchnorrPublicKey
	Secret abstract.Scalar // Scalar representing secret key
}

func (k *SchnorrSecretKey) Init(suite *abstract.Suite) *SchnorrSecretKey {
	k.SchnorrPublicKey.Init(suite)
	return k
}

func (k *SchnorrSecretKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s secret: %s",
		k.Point.String(), k.Secret.String())
}

func (k *SchnorrSecretKey) Pick(rand cipher.Stream) SecretKey {
	k.Secret = k.Suite.Scalar().Random(rand)
	k.Point = k.Suite.Point().BaseMul(k.Secret)
	return k
}

func (k *SchnorrSecretKey) Sign(sig []byte, hash hash.Hash,
	rand cipher.Stream) ([]byte, error) {
	suite := k.Suite

	// Create random secret v and public point commitment T
	v := suite.Scalar().Random(rand)
	T := suite.Point().BaseMul(v)

	// Update the hash to depend on the point commitment
	_, err := T.Marshal(suite.Context(), hash)
	if err != nil {
		return nil, err
	}

	// Use the resulting hash to generate a Schnorr challenge
	hb := hash.Sum(nil)
	c := suite.Scalar().Random(random.ByteStream(hb))

	// Compute response r = v - x*c
	r := suite.Scalar()
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

func (k *SchnorrSecretKey) Marshal(ctx context.Context, w io.Writer) (int, error) {
	return k.Secret.Marshal(ctx, w)
}

func (k *SchnorrSecretKey) UnmarshalBinary(b []byte) error {
	if k.Secret.Nil() {
		k.Secret = k.Suite.Scalar()
	}
	if err := k.Secret.UnmarshalBinary(b); err != nil {
		return err
	}
	k.Point = k.Suite.Point().BaseMul(k.Secret)
	return nil
}

func (k *SchnorrSecretKey) Unmarshal(ctx context.Context, r io.Reader) (int, error) {
	if k.Secret.Nil() {
		k.Secret = k.Suite.Scalar()
	}
	n, err := k.Secret.Unmarshal(ctx, r)
	if err != nil {
		return n, err
	}
	k.Point = k.Suite.Point().BaseMul(k.Secret)
	return n, nil
}
