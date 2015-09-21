package schnorr

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sig"
	"hash"
	"io"
)

func SecretKey(suite abstract.Suite, rand cipher.Stream) sig.SecretKey {
	return &secKey{pubKey{suite, rand, nil}, nil}
}

type secKey struct {
	pub pubKey
	sec abstract.Secret
}

func (k *secKey) String() string {
	return fmt.Sprintf("Schnorr public key: %s secret: %s",
		k.pub.key.String(), k.sec.String())
}

func (k *secKey) Hash() hash.Hash {
	return k.pub.Hash()
}

func (k *secKey) SigSize() int {
	return k.pub.SigSize()
}

func (k *secKey) Pick() sig.SecretKey {
	k.sec = k.pub.suite.Secret().Pick(k.pub.rand)
	k.pub.key = k.pub.suite.Point().Mul(nil, k.sec)
	return k
}

func (k *secKey) Verify(sig []byte, hash hash.Hash) error {
	return k.pub.Verify(sig, hash)
}

func (k *secKey) Sign(sig []byte, hash hash.Hash) ([]byte, error) {
	suite := k.pub.suite

	// Create random secret v and public point commitment T
	v := suite.Secret().Pick(k.pub.rand)
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

func (k *secKey) PublicKey() sig.PublicKey {
	return &k.pub
}

func (k *secKey) MarshalSize() int {
	return k.sec.MarshalSize()
}

func (k *secKey) MarshalBinary() ([]byte, error) {
	return k.sec.MarshalBinary()
}

func (k *secKey) MarshalTo(w io.Writer) (int, error) {
	return k.sec.MarshalTo(w)
}

func (k *secKey) UnmarshalBinary(b []byte) error {
	if k.sec == nil {
		k.sec = k.pub.suite.Secret()
	}
	if err := k.sec.UnmarshalBinary(b); err != nil {
		return err
	}
	k.pub.key = k.pub.suite.Point().Mul(nil, k.sec)
	return nil
}

func (k *secKey) UnmarshalFrom(r io.Reader) (int, error) {
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
