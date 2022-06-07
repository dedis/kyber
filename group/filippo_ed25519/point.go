package filippo_ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
<<<<<<< HEAD
<<<<<<< HEAD
	filippo_ed25519 "filippo.io/edwards25519"
	"go.dedis.ch/kyber/v3"
	"io"
)

type Point struct {
	point *filippo_ed25519.Point
}

func (p *Point) Equal(s2 kyber.Point) bool {
	return p.point.Equal(s2.(*Point).point) == 1
}

func (p *Point) Null() kyber.Point {
	p.point = filippo_ed25519.NewIdentityPoint()
	return p
}

func (p *Point) Base() kyber.Point {
	p.point = filippo_ed25519.NewGeneratorPoint()
	return p
}

func (p *Point) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

func (p *Point) Set(a kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Set(a.(*Point).point)
	return p
}

func (p *Point) Clone() kyber.Point {
	p2 := new(Point)
	p2.point = new(filippo_ed25519.Point)
	p2.point.Set(p.point)
	return p2
}
func (p *Point) Add(a, b kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Add(a.(*Point).point, b.(*Point).point)
	return p
}

func (p *Point) Sub(a, b kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Subtract(a.(*Point).point, b.(*Point).point)
	return p
}

func (p *Point) Neg(a kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Negate(a.(*Point).point)
	return p
}

func (p *Point) Mul(a kyber.Scalar, b kyber.Point) kyber.Point {
	if p == nil || p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	if b == nil || b.(*Point).point == nil {
		p.point = p.point.ScalarBaseMult(a.(*Scalar).scalar)
	} else {
		p.point.ScalarMult(a.(*Scalar).scalar, b.(*Point).point)
	}
	return p
}

func (p *Point) EmbedLen() int {
=======
=======
	filippo_ed25519 "filippo.io/edwards25519"
>>>>>>> Filippo integration completed
	"go.dedis.ch/kyber/v3"
	"io"
)

type Point struct {
	point *filippo_ed25519.Point
}

func (p *Point) Equal(s2 kyber.Point) bool {
	return p.point.Equal(s2.(*Point).point) == 1
}

func (p *Point) Null() kyber.Point {
	p.point = filippo_ed25519.NewIdentityPoint()
	return p
}

func (p *Point) Base() kyber.Point {
	p.point = filippo_ed25519.NewGeneratorPoint()
	return p
}

func (p *Point) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

func (p *Point) Set(a kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Set(a.(*Point).point)
	return p
}

func (p *Point) Clone() kyber.Point {
	p2 := *p
	return &p2
}
<<<<<<< HEAD

func (P *point) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

// Equality test for two Points on the same curve
func (P *point) Equal(P2 kyber.Point) bool {
	b1, _ := P.MarshalBinary()
	b2, _ := P2.(*point).MarshalBinary()
	fp1, _ := filippo_ed25519.NewIdentityPoint().SetBytes(b1)
	fp2, _ := filippo_ed25519.NewIdentityPoint().SetBytes(b2)
	return fp1.Equal(fp2) == 1
}

// Set point to be equal to P2.
func (P *point) Set(P2 kyber.Point) kyber.Point {
	P.ge = P2.(*point).ge
	return P
=======
func (p *Point) Add(a, b kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Add(a.(*Point).point, b.(*Point).point)
	return p
>>>>>>> Filippo integration completed
}

func (p *Point) Sub(a, b kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Subtract(a.(*Point).point, b.(*Point).point)
	return p
}

func (p *Point) Neg(a kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	p.point.Negate(a.(*Point).point)
	return p
}

func (p *Point) Mul(a kyber.Scalar, b kyber.Point) kyber.Point {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	if b == nil || b.(*Point).point == nil {
		p.point = p.point.ScalarBaseMult(a.(*Scalar).scalar)
	} else {
		p.point.VarTimeMultiScalarMult([]*filippo_ed25519.Scalar{a.(*Scalar).scalar}, []*filippo_ed25519.Point{b.(*Point).point})
	}
	return p
}

<<<<<<< HEAD
func (P *point) EmbedLen() int {
>>>>>>> Docs added and filippo integration initiated
=======
func (p *Point) EmbedLen() int {
>>>>>>> Filippo integration completed
	// Reserve the most-significant 8 bits for pseudo-randomness.
	// Reserve the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

<<<<<<< HEAD
<<<<<<< HEAD
func (p *Point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := p.EmbedLen()
=======
func (P *point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := P.EmbedLen()
>>>>>>> Docs added and filippo integration initiated
=======
func (p *Point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := p.EmbedLen()
>>>>>>> Filippo integration completed
	if dl > len(data) {
		dl = len(data)
	}

<<<<<<< HEAD
<<<<<<< HEAD
	p.point = new(filippo_ed25519.Point)

=======
>>>>>>> Docs added and filippo integration initiated
=======
	p.point = new(filippo_ed25519.Point)

>>>>>>> Filippo integration completed
	for {
		// Pick a random point, with optional embedded data
		var b [32]byte
		rand.XORKeyStream(b[:], b[:])
		if data != nil {
			b[0] = byte(dl)       // Encode length in low 8 bits
			copy(b[1:1+dl], data) // Copy in data to embed
		}
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Filippo integration completed

		_, err := p.point.SetBytes(b[:])
		if err != nil {
			continue
<<<<<<< HEAD
		}

		if data == nil {
			p.Mul(filippoCofactorScalar, p)
			if p.Equal(&filippoNullPoint) {
				continue
			}
			return p
=======
		if !P.ge.FromBytes(b[:]) { // Try to decode
			continue // invalid point, retry
=======
>>>>>>> Filippo integration completed
		}

		if data == nil {
			p.Mul(filippoCofactorScalar, p)
			if p.Equal(&filippoNullPoint) {
				continue
			}
<<<<<<< HEAD
			return P // success
>>>>>>> Docs added and filippo integration initiated
=======
			return p
>>>>>>> Filippo integration completed
		}

		// Since we need the point's y-coordinate to hold our data,
		// we must simply check if the point is in the subgroup
		// and retry point generation until it is.
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Filippo integration completed
		var Q Point
		Q.Mul(filippoPrimeOrderScalar, p)
		if Q.Equal(&filippoNullPoint) {
			return p // success
<<<<<<< HEAD
		}
		// setCannonicalBytes()
=======
		var Q point
		Q.Mul(primeOrderScalar, P)
		if Q.Equal(nullPoint) {
			return P // success
		}
>>>>>>> Docs added and filippo integration initiated
=======
		}
		// setCannonicalBytes()
>>>>>>> Filippo integration completed
		// Keep trying...
	}
}

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Filippo integration completed
func (p *Point) Data() ([]byte, error) {
	if p.point == nil {
		return nil, errors.New("point not initialized")
	}

	b := p.point.Bytes()
	dl := int(b[0])
	if dl > p.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[1 : 1+dl], nil
}

func (p *Point) MarshalSize() int {
	return 32
}

func (p *Point) String() string {
	b := p.point.Bytes()
	return hex.EncodeToString(b)
}

func (p *Point) MarshalBinary() ([]byte, error) {
	if p.point == nil {
		return nil, errors.New("point not initialized")
	}
	return p.point.Bytes(), nil
}

func (p *Point) MarshalID() []byte {
	return marshalPointID[:]
}

func (p *Point) UnmarshalBinary(b []byte) error {
	if p.point == nil {
		p.point = new(filippo_ed25519.Point)
	}
	_, err := p.point.SetBytes(b)
	return err
}

func (p *Point) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *Point) UnmarshalFrom(r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		p.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
<<<<<<< HEAD
=======
func (P *point) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Extract embedded data from a point group element
func (P *point) Data() ([]byte, error) {
	return []byte{}, nil
}

func (P *point) Add(P1, P2 kyber.Point) kyber.Point {
	return nil
}

func (P *point) Sub(P1, P2 kyber.Point) kyber.Point {
	return nil
}

// Neg finds the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *point) Neg(A kyber.Point) kyber.Point {
	return nil
}

//func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {
//	b1, _ := A.(*point).MarshalBinary()
//	fp1, _ := filippo_ed25519.NewIdentityPoint().SetBytes(b1)
//	b2, _ := s.(*scalar).MarshalBinary()
//	fs2, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(b2)
//	//ans := filippo_ed25519.NewIdentityPoint().VarTimeMultiScalarMult([]*filippo_ed25519.Scalar{fs2}, []*filippo_ed25519.Point{fp1})
//	ans := filippo_ed25519.NewIdentityPoint().ScalarMult(fs2, fp1)
//	P.UnmarshalBinary(ans.Bytes())
//	return nil
//}

func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {
	//b1, _ := A.(*point).MarshalBinary()
	b1 := []byte{48, 189, 120, 52, 214, 153, 57, 176, 74, 4, 78, 97, 103, 85, 224, 99, 98, 78, 100, 216, 88, 14, 23, 222, 44, 61, 152, 82, 209, 243, 248, 188}
	b2 := []byte{100, 8, 188, 29, 221, 44, 54, 97, 129, 110, 7, 249, 145, 95, 32, 44, 67, 14, 73, 78, 28, 178, 136, 76, 125, 179, 228, 94, 104, 126, 124, 15}
	fp1, _ := filippo_ed25519.NewIdentityPoint().SetBytes(b1)
	//b2, _ := s.(*scalar).MarshalBinary()
	fs2, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(b2)
	//ans := filippo_ed25519.NewIdentityPoint().VarTimeMultiScalarMult([]*filippo_ed25519.Scalar{fs2}, []*filippo_ed25519.Point{fp1})
	ans := filippo_ed25519.NewIdentityPoint().ScalarMult(fs2, fp1)
	_ = ans
	//P.UnmarshalBinary(ans.Bytes())
	return nil
>>>>>>> Docs added and filippo integration initiated
=======
>>>>>>> Filippo integration completed
}
