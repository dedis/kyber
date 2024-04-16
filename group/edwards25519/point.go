// Package edwards25519 provides an optimized Go implementation of a
// Twisted Edwards curve that is isomorphic to Curve25519. For details see:
// http://ed25519.cr.yp.to/.
//
// This code is based on Adam Langley's Go port of the public domain,
// "ref10" implementation of the ed25519 signing scheme in C from SUPERCOP.
// It was generalized and extended to support full kyber.Group arithmetic
// by the DEDIS lab at Yale and EPFL.
//
// Due to the field element and group arithmetic optimizations
// described in the Ed25519 paper, this implementation generally
// performs extremely well, typically comparable to native C
// implementations.  The tradeoff is that this code is completely
// specialized to a single curve.
package edwards25519

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"math"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"golang.org/x/xerrors"
)

var marshalPointID = [8]byte{'e', 'd', '.', 'p', 'o', 'i', 'n', 't'}

type point struct {
	ge      extendedGroupElement
	varTime bool
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

// MarshalID returns the type tag used in encoding/decoding
func (P *point) MarshalID() [8]byte {
	return marshalPointID
}

func (P *point) UnmarshalBinary(b []byte) error {
	if !P.ge.FromBytes(b) {
		return xerrors.New("invalid Ed25519 curve point")
	}
	return nil
}

func (P *point) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(P, w)
}

func (P *point) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

// Equality test for two Points on the same curve
func (P *point) Equal(P2 kyber.Point) bool {

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
func (P *point) Set(P2 kyber.Point) kyber.Point {
	P.ge = P2.(*point).ge
	return P
}

// Set point to be equal to P2.
func (P *point) Clone() kyber.Point {
	return &point{ge: P.ge}
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *point) Null() kyber.Point {
	P.ge.Zero()
	return P
}

// Set to the standard base point for this curve
func (P *point) Base() kyber.Point {
	P.ge = baseext
	return P
}

func (P *point) EmbedLen() int {
	// Reserve the most-significant 8 bits for pseudo-randomness.
	// Reserve the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (P *point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := P.EmbedLen()
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
		// so we need to make sure the point is in that subencoding.
		// If we're not trying to embed data,
		// we can convert our point into one in the subgroup
		// simply by multiplying it by the cofactor.
		if data == nil {
			P.Mul(cofactorScalar, P) // multiply by cofactor
			if P.Equal(nullPoint) {
				continue // unlucky; try again
			}
			return P // success
		}

		// Since we need the point's y-coordinate to hold our data,
		// we must simply check if the point is in the subgroup
		// and retry point generation until it is.
		var Q point
		Q.Mul(primeOrderScalar, P)
		if Q.Equal(nullPoint) {
			return P // success
		}
		// Keep trying...
	}
}

func (P *point) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Extract embedded data from a point group element
func (P *point) Data() ([]byte, error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	dl := int(b[0]) // extract length byte
	if dl > P.EmbedLen() {
		return nil, xerrors.New("invalid embedded data length")
	}
	return b[1 : 1+dl], nil
}

func (P *point) Add(P1, P2 kyber.Point) kyber.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Add(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	return P
}

func (P *point) Sub(P1, P2 kyber.Point) kyber.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Sub(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	return P
}

// Neg finds the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *point) Neg(A kyber.Point) kyber.Point {
	P.ge.Neg(&A.(*point).ge)
	return P
}

// Mul multiplies point p by scalar s using the repeated doubling method.
func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {

	a := &s.(*scalar).v

	if A == nil {
		geScalarMultBase(&P.ge, a)
	} else {
		if P.varTime {
			geScalarMultVartime(&P.ge, a, &A.(*point).ge)
		} else {
			geScalarMult(&P.ge, a, &A.(*point).ge)
		}
	}

	return P
}

// HasSmallOrder determines whether the group element has small order
//
// Provides resilience against malicious key substitution attacks (M-S-UEO)
// and message bound security (MSB) even for malicious keys
// See paper https://eprint.iacr.org/2020/823.pdf for definitions and theorems
//
// This is the same code as in
// https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1170
func (P *point) HasSmallOrder() bool {
	s, err := P.MarshalBinary()
	if err != nil {
		return false
	}

	var c [5]byte

	for j := 0; j < 31; j++ {
		for i := 0; i < 5; i++ {
			c[i] |= s[j] ^ weakKeys[i][j]
		}
	}
	for i := 0; i < 5; i++ {
		c[i] |= (s[31] & 0x7f) ^ weakKeys[i][31]
	}

	// Constant time verification if one or more of the c's are zero
	var k uint16
	for i := 0; i < 5; i++ {
		k |= uint16(c[i]) - 1
	}

	return (k>>8)&1 > 0
}

// IsCanonical determines whether the group element is canonical
//
// Checks whether group element s is less than p, according to RFC8032§5.1.3.1
// https://tools.ietf.org/html/rfc8032#section-5.1.3
//
// Taken from
// https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1113
//
// The method accepts a buffer instead of calling `MarshalBinary` on the receiver
// because that always returns a value modulo `prime`.
func (P *point) IsCanonical(s []byte) bool {
	if len(s) != 32 {
		return false
	}

	c := (s[31] & 0x7f) ^ 0x7f
	for i := 30; i > 0; i-- {
		c |= s[i] ^ 0xff
	}

	// subtraction might underflow
	c = byte((uint16(c) - 1) >> 8)
	d := byte((0xed - 1 - uint16(s[0])) >> 8)

	return 1-(c&d&1) == 1
}

func (P *point) Hash(m []byte, dst string) kyber.Point {
	u := hashToField(m, dst, 2)
	q0 := mapToCurveElligator2Ed25519(u[0])
	q1 := mapToCurveElligator2Ed25519(u[1])
	P.Add(q0, q1)

	// Clear cofactor
	h := newScalarInt(big.NewInt(8))
	P.Mul(h, P)

	return P
}

func hashToField(m []byte, dst string, count int) []fieldElement {
	l := 48 // L param in RFC9380
	byteLen := count * l
	uniformBytes, _ := expandMessageXMD(sha512.New(), m, dst, byteLen)

	u := make([]fieldElement, count)
	for i := 0; i < count; i++ {
		elmOffset := l * i
		tv := big.NewInt(0).SetBytes(uniformBytes[elmOffset : elmOffset+l])
		tv = tv.Mod(tv, prime)
		fe := fieldElement{}
		feFromBn(&fe, tv)
		u[i] = fe
	}

	return u
}

func expandMessageXMD(h hash.Hash, m []byte, domainSeparator string, byteLen int) ([]byte, error) {
	r := float64(byteLen) / float64(h.Size()>>3)
	ell := int(math.Ceil(r))
	if ell > 255 || ell < 0 || byteLen > 65535 || len(domainSeparator) > 255 {
		return nil, xerrors.New("invalid parameters")
	}

	padDom, err := i2OSP(len(domainSeparator), 1)
	if err != nil {
		return nil, err
	}

	dstPrime := append([]byte(domainSeparator), padDom...)
	byteLenStr, _ := i2OSP(byteLen, 2)
	zeroPad, _ := i2OSP(0, 1)
	zPad, _ := i2OSP(0, h.BlockSize())

	// mPrime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prim
	mPrime := make([]byte, 0, len(zPad)+len(m)+len(byteLenStr)+len(zeroPad)+len(dstPrime))
	mPrime = append(mPrime, zPad...)
	mPrime = append(mPrime, m...)
	mPrime = append(mPrime, byteLenStr...)
	mPrime = append(mPrime, zeroPad...)
	mPrime = append(mPrime, dstPrime...)

	// b0 = H(msg_prime)
	h.Reset()
	h.Write([]byte(mPrime))
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime
	h.Reset()
	h.Write(b0)
	onePad, _ := i2OSP(1, 1)
	h.Write([]byte(onePad))
	h.Write([]byte(dstPrime))
	b1 := h.Sum(nil)

	bFinal := make([]byte, 0, len(b1)*(ell+1))
	bFinal = append(bFinal, b1...)
	bPred := b1
	for i := 2; i <= ell; i++ {
		x, err := byteXor(bPred, b0, bPred)
		if err != nil {
			return nil, err
		}
		ithPad, _ := i2OSP(i, 1)

		h.Reset()
		h.Write(x)
		h.Write(ithPad)
		h.Write(dstPrime)

		bPred = h.Sum(nil)
		bFinal = append(bFinal, bPred...)
	}

	return bFinal[:byteLen], nil
}

func i2OSP(x int, xLen int) ([]byte, error) {
	b := big.NewInt(int64(x))
	s := b.Bytes()
	if len(s) > xLen {
		return nil, xerrors.Errorf("input %d superior to max length %d", len(s), xLen)
	}

	pad := make([]byte, (xLen - len(s)))
	return append(pad, s...), nil
}

func byteXor(dst, b1, b2 []byte) ([]byte, error) {
	if !(len(dst) == len(b1) && len(b2) == len(b1)) {
		return nil, xerrors.New("incompatible lenghs")
	}

	for i := 0; i < len(dst); i++ {
		dst[i] = b1[i] ^ b2[i]
	}

	return dst, nil
}

func curve25519Elligator2(u fieldElement) (xn, xd, yn, yd fieldElement) {
	// Some const needed
	var one fieldElement
	feOne(&one)

	// c1 = (q + 3) / 8
	// c2 = 2^c1
	// c3 = sqrt(-1)
	// c4 = (q - 5) / 8
	// Computed with sagemath
	c2 := fieldElement{34513073, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654, 31548777, 326685, 11406482}
	c3 := fieldElement{34513072, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654, 31548777, 326685, 11406482}
	c4 := fieldElement{67108861, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 4194303}
	c4Big, _ := new(big.Int).SetString("7237005577332262213973186563042994240829374041602535252466099000494570602493", 10)

	var j fieldElement
	j[0] = 486664

	// Temporary variables
	var tv1, tv2, tv3, x1n, gxd, gx1, gx2 fieldElement
	var y, y1, y2, y11, y12, y21, y22, x2n fieldElement
	var e1, e2, e3, e4 int32

	feSquare2(&tv1, &u)

	feAdd(&xd, &one, &tv1)
	feNeg(&x1n, &j)
	feSquare(&tv2, &xd)
	feMul(&gxd, &tv2, &xd)
	feMul(&gx1, &j, &tv1)
	feMul(&gx1, &gx1, &x1n)
	feAdd(&gx1, &gx1, &tv2)
	feMul(&gx1, &gx1, &x1n)
	feSquare(&tv3, &gxd)
	feSquare(&tv2, &tv3)
	feMul(&tv3, &tv3, &gxd)
	feMul(&tv3, &tv3, &gx1)
	feMul(&tv2, &tv2, &tv3)

	// compute y11 = tv2 ^ c4
	tv2Big := big.NewInt(0)
	feToBn(tv2Big, &c4)
	y11Big := big.NewInt(0).Exp(tv2Big, c4Big, prime)
	feFromBn(&y11, y11Big)

	feMul(&y11, &y11, &tv3)
	feMul(&y12, &y11, &c3)
	feSquare(&tv2, &y11)
	feMul(&tv2, &tv2, &gxd)
	if tv2 == gx1 {
		e1 = 1
	}

	feCopy(&y1, &y12)
	feCMove(&y1, &y11, e1)
	feMul(&x2n, &x1n, &tv1)
	feMul(&y21, &y11, &u)
	feMul(&y21, &y21, &c2)
	feMul(&y22, &y21, &c3)
	feMul(&gx2, &gx1, &tv1)
	feSquare(&tv2, &y21)
	feMul(&tv2, &tv2, &gxd)
	if tv2 == gx2 {
		e2 = 1
	}

	feCopy(&y2, &y22)
	feCMove(&y2, &y21, e2)
	feSquare(&tv2, &y1)
	feMul(&tv2, &tv2, &gxd)
	if tv2 == gx1 {
		e3 = 1
	}

	feCopy(&xn, &x2n)
	feCMove(&xn, &x1n, e3)
	feCopy(&y, &y2)
	feCMove(&y, &y1, e3)
	e4 = int32(feIsNegative(&y))
	var yNeg fieldElement
	feNeg(&yNeg, &y)
	feCMove(&y, &yNeg, e3^e4)

	return xn, xd, y, one
}

func mapToCurveElligator2Ed25519(u fieldElement) kyber.Point {
	var xn, xd, yn, yd fieldElement
	var zero, one, tv1 fieldElement
	var e int32
	feOne(&one)

	// c = sqrt(-486664)
	// computed using sagemath
	c := fieldElement{67108861, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 4194303}

	xMn, xMd, yMn, yMd := curve25519Elligator2(u)

	feMul(&xn, &xMn, &yMd)
	feMul(&xn, &xn, &c)
	feMul(&xd, &xMd, &yMn)
	feSub(&yn, &xMn, &xMd)
	feAdd(&yd, &xMn, &xMd)
	feMul(&tv1, &xd, &yd)
	if tv1 == zero {
		e = 1
	}

	feCMove(&xn, &zero, e)
	feCMove(&xd, &one, e)
	feCMove(&yn, &one, e)
	feCMove(&yd, &one, e)

	p := completedGroupElement{
		X: xn,
		Y: yn,
		Z: xd,
		T: yd,
	}

	q := new(point)
	p.ToExtended(&q.ge)

	return q
}
