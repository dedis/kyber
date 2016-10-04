// Package ed25519 provides an optimized Go implementation of a
// Twisted Edwards curve that is isomorphic to Curve25519. For details see:
// http://ed25519.cr.yp.to/.
//
// This code is based on Adam Langley's Go port of the public domain,
// "ref10" implementation of the ed25519 signing scheme in C from SUPERCOP.
// It was generalized and extended to support full abstract group arithmetic
// by the Yale Decentralized/Distributed Systems (DeDiS) group.
//
// Due to the field element and group arithmetic optimizations
// described in the Ed25519 paper, this implementation generally performs
// extremely well, typically comparable to native C implementations.
// The tradeoff is that this code is completely specialized to a single curve.
//
package ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/nist"
)

type point struct {
	ge extendedGroupElement
}

func (P *point) String() string {
	var b [32]byte
	P.ge.ToBytes(&b)
	return hex.EncodeToString(b[:])
}

func (P *point) MarshalSize() int {
	return 32
}

func (P *point) MarshalBinary() ([]byte, error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	return b[:], nil
}

func (P *point) UnmarshalBinary(b []byte) error {
	if !P.ge.FromBytes(b) {
		return errors.New("invalid Ed25519 curve point")
	}
	return nil
}

func (P *point) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(P, w)
}

func (P *point) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(P, r)
}

// Equality test for two Points on the same curve
func (P *point) Equal(P2 abstract.Point) bool {

	// XXX better to test equality without normalizing extended coords

	var b1, b2 [32]byte
	P.ge.ToBytes(&b1)
	P2.(*point).ge.ToBytes(&b2)
	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

// Set point to be equal to P2.
func (P *point) Set(P2 abstract.Point) abstract.Point {
	P.ge = P2.(*point).ge
	return P
}

// Set point to be equal to P2.
func (P *point) Clone() abstract.Point {
	return &point{ge: P.ge}
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *point) Null() abstract.Point {
	P.ge.Zero()
	return P
}

// Set to the standard base point for this curve
func (P *point) Base() abstract.Point {
	P.ge = baseext
	return P
}

func (P *point) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (P *point) Pick(data []byte, rand cipher.Stream) (abstract.Point, []byte) {

	// How many bytes to embed?
	dl := P.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		// Pick a random point, with optional embedded data
		var b [32]byte
		rand.XORKeyStream(b[:], b[:])
		if data != nil {
			b[0] = byte(dl)       // Encode length in low 8 bits
			copy(b[1:1+dl], data) // Copy in data to embed
		}
		if !P.ge.FromBytes(b[:]) { // Try to decode
			continue // invalid point, retry
		}

		// If we're using the full group,
		// we just need any point on the curve, so we're done.
		//		if c.full {
		//			return P,data[dl:]
		//		}

		// We're using the prime-order subgroup,
		// so we need to make sure the point is in that subgroup.
		// If we're not trying to embed data,
		// we can convert our point into one in the subgroup
		// simply by multiplying it by the cofactor.
		if data == nil {
			P.Mul(P, cofactor) // multiply by cofactor
			if P.Equal(nullPoint) {
				continue // unlucky; try again
			}
			return P, data[dl:] // success
		}

		// Since we need the point's y-coordinate to hold our data,
		// we must simply check if the point is in the subgroup
		// and retry point generation until it is.
		var Q point
		Q.Mul(P, primeOrder)
		if Q.Equal(nullPoint) {
			return P, data[dl:] // success
		}

		// Keep trying...
	}
}

// Extract embedded data from a point group element
func (P *point) Data() ([]byte, error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	dl := int(b[0]) // extract length byte
	if dl > P.PickLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[1 : 1+dl], nil
}

func (P *point) Add(P1, P2 abstract.Point) abstract.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Add(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	// XXX in this case better just to use general addition formula?

	return P
}

func (P *point) Sub(P1, P2 abstract.Point) abstract.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Sub(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	// XXX in this case better just to use general addition formula?

	return P
}

// Find the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *point) Neg(A abstract.Point) abstract.Point {
	P.ge.Neg(&A.(*point).ge)
	return P
}

// Multiply point p by scalar s using the repeated doubling method.
// XXX This is vartime; for our general-purpose Mul operator
// it would be far preferable for security to do this constant-time.
func (P *point) Mul(A abstract.Point, s abstract.Scalar) abstract.Point {

	// Convert the scalar to fixed-length little-endian form.
	sb := s.(*nist.Int).V.Bytes()
	shi := len(sb) - 1
	var a [32]byte
	for i := range sb {
		a[shi-i] = sb[i]
	}

	if A == nil {
		geScalarMultBase(&P.ge, &a)
	} else {
		geScalarMult(&P.ge, &a, &A.(*point).ge)
		//geScalarMultVartime(&P.ge, &a, &A.(*point).ge)
	}

	return P
}

// Curve represents an Ed25519.
// There are no parameters and no initialization is required
// because it supports only this one specific curve.
type Curve struct {

	// Set to true to use the full group of order 8Q,
	// or false to use the prime-order subgroup of order Q.
	//	FullGroup bool
}

func (c *Curve) PrimeOrder() bool {
	return true
}

// Return the name of the curve, "Ed25519".
func (c *Curve) String() string {
	return "Ed25519"
}

// Returns 32, the size in bytes of an encoded Scalar for the Ed25519 curve.
func (c *Curve) ScalarLen() int {
	return 32
}

// Create a new Scalar for the Ed25519 curve.
func (c *Curve) Scalar() abstract.Scalar {
	//	if c.FullGroup {
	//		return nist.NewInt(0, fullOrder)
	//	} else {
	i := nist.NewInt64(0, &primeOrder.V)
	i.BO = nist.LittleEndian
	return i
	//	}
}

// Returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
func (c *Curve) PointLen() int {
	return 32
}

// Create a new Point on the Ed25519 curve.
func (c *Curve) Point() abstract.Point {
	P := new(point)
	//P.c = c
	return P
}

// Initialize the curve.
//func (c *Curve) Init(fullGroup bool) {
//	c.FullGroup = fullGroup
//}
