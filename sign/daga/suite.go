package daga

import (
	"crypto/cipher"
	"crypto/sha256"
	"github.com/dedis/fixbuf"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake2xb"
	"hash"
	"io"
	"reflect"
)

// SuiteEC is the EC crypto concrete implementation of the DAGA Suite interface,
// it is used to implement DAGA on the twisted Edwards curve that is birationally equivalent to Curve25519
// (i.e. the suite uses the same curve that is used in Ed25519's EdDSA signature scheme)
// TODO there are naming issues related to the curves in Kyber => create discussion
type suiteEC struct {
	edwards25519.Curve
}

// Returns a new Suite backed by a suiteEC
func NewSuiteEC() Suite {
	return new(suiteEC)
}

// returns new hash.Hash computing the SHA-256 checksum
// this hash is used in DAGA to derive valid Scalars of the group used
func (s suiteEC) Hash() hash.Hash {
	// FIXME QUESTION are length extension attacks considered to be feasible on sha256 and should we care (we don't use it to build MAC's then...) ?
	// QUESTION maybe instead use sha512/256 ? (which should be faster on 64 bit architectures)
	// and finally see the Hash related comment on Suite
	return sha256.New()
}

func (s suiteEC) hashTwo() hash.Hash {
	// QUESTION same as above
	return sha256.New()
}

func (s suiteEC) RandomStream() cipher.Stream {
	return random.New()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// used to give to the kyber.proof framework/package the methods it needs to operate, satisfy both proof.Suite and daga.Suite
type SuiteProof struct {
	Suite
}

func newSuiteProof(suite Suite) SuiteProof {
	return SuiteProof{suite}
}

// XOF returns an XOF which is implemented via the Blake2b hash.
func (s SuiteProof) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

func (s SuiteProof) Write(w io.Writer, objs ...interface{}) error {
	// TODO/QUESTION what codec to choose ?
	return fixbuf.Write(w, objs)
}

func (s SuiteProof) Read(r io.Reader, objs ...interface{}) error {
	// TODO/QUESTION what codec to choose ?
	return fixbuf.Read(r, s, objs...)
}

// New implements the kyber.Encoding interface, needed to satisfy the kyber.Proof.Suite interface
func (s SuiteProof) New(t reflect.Type) interface{} {
	// QUESTION FIXME not totally sure if this is working, but a quick go playground hints it is ok.. https://play.golang.org/p/pkcd2RzlZad
	// TODO if this is ok, this implementation might be better that the one used in group/internal/marshalling/marshal.go
	// TODO (and to my current understanding completely equivalent...only no need to have those package vars only to get their reflect type)
	scalarInterface := reflect.TypeOf((*kyber.Scalar)(nil)).Elem()
	pointInterface := reflect.TypeOf((*kyber.Point)(nil)).Elem()
	if t.Implements(scalarInterface) {
		return s.Scalar()
	} else if t.Implements(pointInterface) {
		return s.Point()
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO if time, concrete implementation that uses same primitives that in DAGA paper (work in a schnorr group)
// TODO QUESTION did someone already implemented a kyber Schnorr group somewhere ?
//type SuiteSchnorr struct {
//	mod.Int
//}
//
//func (s SuiteSchnorr) Hash() hash.Hash {
//	return sha256.New()
//}
//
//func (s SuiteSchnorr) NewKey(random cipher.Stream) kyber.Scalar {
//	return s.Scalar().Pick(random)
//}
//
//func (s SuiteSchnorr) Scalar() kyber.Scalar {
//	return mod.NewInt(nil, s.)
//}
//
//func (s SuiteSchnorr) Point() kyber.Point {
//	return nil
//}
//
//func () Base() kyber.Point {
//}
//
////func newSuiteSchnorr() Suite {
////	return new(SuiteSchnorr)
////}
