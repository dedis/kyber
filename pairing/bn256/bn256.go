package bn256

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/fixbuf"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake"
)

// SuiteBN256 implements the PairingSuite interface for the BN256 bilinear pairing.
type SuiteBN256 struct {
	g1 *groupG1
	g2 *groupG2
	gt *groupGT
	r  cipher.Stream
}

// NewSuiteBN256 ...
func NewSuiteBN256() *SuiteBN256 {
	s := &SuiteBN256{}
	s.g1 = &groupG1{}
	s.g2 = &groupG2{}
	s.gt = &groupGT{}
	return s
}

// NewSuiteBN256Rand ...
func NewSuiteBN256Rand(rand cipher.Stream) *SuiteBN256 {
	s := &SuiteBN256{}
	s.g1 = &groupG1{}
	s.g2 = &groupG2{}
	s.gt = &groupGT{}
	s.r = rand
	return s
}

// G1 ...
func (s *SuiteBN256) G1() kyber.Group {
	return s.g1
}

// G2 ...
func (s *SuiteBN256) G2() kyber.Group {
	return s.g2
}

// GT ...
func (s *SuiteBN256) GT() kyber.Group {
	return s.gt
}

// Pair
func (g *SuiteBN256) Pair(g1 kyber.Point, g2 kyber.Point) kyber.Point {
	return Pair(g1, g2)
}

// Hash ...
func (s *SuiteBN256) Hash() hash.Hash {
	return sha256.New()
}

// XOF ...
func (s *SuiteBN256) XOF(seed []byte) kyber.XOF {
	return blake.New(seed)
}

// Read ...
func (s *SuiteBN256) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs...)
}

// Write ...
func (s *SuiteBN256) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.Encoding interface
func (s *SuiteBN256) New(t reflect.Type) interface{} {
	return nil // TODO
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteBN256) RandomStream() cipher.Stream {
	if s.r != nil {
		return s.r
	}
	return random.New()
}
