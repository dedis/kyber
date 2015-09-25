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

// Create a public key object for Schnorr signatures.
func (s SchnorrScheme) PublicKey() PublicKey {
	return &schnorrPubKey{s, nil}
}

// Create a secret key object for Schnorr signatures.
func (s SchnorrScheme) SecretKey() SecretKey {
	return &schnorrSecKey{schnorrPubKey{s, nil}, nil}
}

///// Schnorr public keys

type schnorrPubKey struct {
	suite abstract.Suite
	key   abstract.Point
}

func (k *schnorrPubKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s", k.key.String())
}

func (k *schnorrPubKey) Hash() hash.Hash {
	return k.suite.Hash()
}

func (k *schnorrPubKey) SigSize() int {
	return k.suite.SecretLen() * 2
}

func (k *schnorrPubKey) Verify(sig []byte, hash hash.Hash) error {
	suite := k.suite

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
	T.Add(T.Mul(nil, r), P.Mul(k.key, c))

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

func (k *schnorrPubKey) MarshalSize() int {
	return k.key.MarshalSize()
}

func (k *schnorrPubKey) MarshalBinary() ([]byte, error) {
	return k.key.MarshalBinary()
}

func (k *schnorrPubKey) MarshalTo(w io.Writer) (int, error) {
	return k.key.MarshalTo(w)
}

func (k *schnorrPubKey) UnmarshalBinary(b []byte) error {
	return k.key.UnmarshalBinary(b)
}

func (k *schnorrPubKey) UnmarshalFrom(r io.Reader) (int, error) {
	return k.key.UnmarshalFrom(r)
}

///// Schnorr secret keys

type schnorrSecKey struct {
	pub schnorrPubKey
	sec abstract.Secret
}

func (k *schnorrSecKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s secret: %s",
		k.pub.key.String(), k.sec.String())
}

func (k *schnorrSecKey) Hash() hash.Hash {
	return k.pub.Hash()
}

func (k *schnorrSecKey) SigSize() int {
	return k.pub.SigSize()
}

func (k *schnorrSecKey) Pick(rand cipher.Stream) SecretKey {
	k.sec = k.pub.suite.Secret().Pick(rand)
	k.pub.key = k.pub.suite.Point().Mul(nil, k.sec)
	return k
}

func (k *schnorrSecKey) Verify(sig []byte, hash hash.Hash) error {
	return k.pub.Verify(sig, hash)
}

func (k *schnorrSecKey) Sign(sig []byte, hash hash.Hash,
	rand cipher.Stream) ([]byte, error) {
	suite := k.pub.suite

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
	r.Mul(k.sec, c).Sub(v, r)

	// Produce verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	suite.Write(&buf, &c, &r)
	return append(sig, buf.Bytes()...), nil
}

func (k *schnorrSecKey) PublicKey() PublicKey {
	return &k.pub
}

func (k *schnorrSecKey) MarshalSize() int {
	return k.sec.MarshalSize()
}

func (k *schnorrSecKey) MarshalBinary() ([]byte, error) {
	return k.sec.MarshalBinary()
}

func (k *schnorrSecKey) MarshalTo(w io.Writer) (int, error) {
	return k.sec.MarshalTo(w)
}

func (k *schnorrSecKey) UnmarshalBinary(b []byte) error {
	if k.sec == nil {
		k.sec = k.pub.suite.Secret()
	}
	if err := k.sec.UnmarshalBinary(b); err != nil {
		return err
	}
	k.pub.key = k.pub.suite.Point().Mul(nil, k.sec)
	return nil
}

func (k *schnorrSecKey) UnmarshalFrom(r io.Reader) (int, error) {
	if k.sec == nil {
		k.sec = k.pub.suite.Secret()
	}
	n, err := k.sec.UnmarshalFrom(r)
	if err != nil {
		return n, err
	}
	k.pub.key = k.pub.suite.Point().Mul(nil, k.sec)
	return n, nil
}
