package schnorr

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sig"
	"hash"
	"io"
)

func PublicKey(suite abstract.Suite, rand cipher.Stream) sig.PublicKey {
	return &pubKey{suite, rand, nil}
}

type pubKey struct {
	suite abstract.Suite
	rand  cipher.Stream
	key   abstract.Point
}

func (k *pubKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s", k.key.String())
}

func (k *pubKey) Hash() hash.Hash {
	return k.suite.Hash()
}

func (k *pubKey) SigSize() int {
	return k.suite.SecretLen() * 2
}

func (k *pubKey) Verify(sig []byte, hash hash.Hash) error {
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

func (k *pubKey) MarshalSize() int {
	return k.key.MarshalSize()
}

func (k *pubKey) MarshalBinary() ([]byte, error) {
	return k.key.MarshalBinary()
}

func (k *pubKey) MarshalTo(w io.Writer) (int, error) {
	return k.key.MarshalTo(w)
}

func (k *pubKey) UnmarshalBinary(b []byte) error {
	return k.key.UnmarshalBinary(b)
}

func (k *pubKey) UnmarshalFrom(r io.Reader) (int, error) {
	return k.key.UnmarshalFrom(r)
}
