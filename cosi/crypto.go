package cosi

import (
	"crypto/sha512"
	"math/big"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/util"
)

// secretToSlice takes a secret and returns the slice representation in little
// endian as in EdDSA.
// NOTE: currently, an abstract.Secret is already modulo'd, so the
// representation is not quite the same as a *real* EdDSA private key as it is
// normally *not* modulo'd but simply taken as a *raw* slice of bytes.
func secretToSlice(secret abstract.Secret) []byte {
	i := secret.(*nist.Int)
	min := 32
	max := 32
	act := i.MarshalSize()
	vSize := len(i.V.Bytes())
	if vSize < act {
		act = vSize
	}
	pad := act
	if pad < min {
		pad = min
	}
	if max != 0 && pad > max {
		panic("Int not representable in max bytes")
	}
	buf := make([]byte, pad)
	util.Reverse(buf[:act], i.V.Bytes())
	return buf
}

// sliceToSecret will return a Secret out of a raw slice of bytes.
// NOTE: Similar to secretToSlice, it will modulo'd the secret if not already.
func sliceToSecret(suite abstract.Suite, buffer []byte) abstract.Secret {
	s := suite.Secret().(*nist.Int)
	s.SetLittleEndian(buffer)
	return s
}

// Ed25519ToPublic will transform a ed25519 scalar to a ed25519 EDDSA formated public key using
// the digest + prune transofrmation
func Ed25519ToPublic(suite abstract.Suite, s abstract.Secret) abstract.Point {
	// secret modulo-d
	//secMarshal := s.(*nist.Int).LittleEndian(32, 32)
	secMarshal := secretToSlice(s)
	pruned := sha512.Sum512(secMarshal)
	pruned[0] &= 248
	pruned[31] &= 127
	pruned[31] |= 64

	// go back to secret, now formatted as ed25519
	//secPruned := SliceToInt(suite, pruned)
	base := big.NewInt(2)
	exp := big.NewInt(256)
	modulo := big.NewInt(0).Exp(base, exp, nil)
	modulo.Sub(modulo, big.NewInt(1))
	secPruned := nist.NewInt(0, modulo)
	secPruned.SetLittleEndian(pruned[:32])
	return suite.Point().Mul(nil, secPruned)
}

// sumPublics is a simple utility that sums public keys and return the aggregate
// public key.
func sumPublics(suite abstract.Suite, publics []abstract.Point) abstract.Point {
	agg := suite.Point().Null()
	for _, p := range publics {
		agg = agg.Add(agg, p)
	}
	return agg
}
