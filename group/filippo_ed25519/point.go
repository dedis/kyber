package filippo_ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	filippo_ed25519 "filippo.io/edwards25519"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"
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
	// Reserve the most-significant 8 bits for pseudo-randomness.
	// Reserve the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (p *Point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := p.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	p.point = new(filippo_ed25519.Point)

	// Github issue raised for the problem of the infinite loop

	for {
		// Pick a random point, with optional embedded data
		var b [32]byte
		rand.XORKeyStream(b[:], b[:])
		if data != nil {
			b[0] = byte(dl)       // Encode length in low 8 bits
			copy(b[1:1+dl], data) // Copy in data to embed
		}

		_, err := p.point.SetBytes(b[:])
		if err != nil {
			continue
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
			p.Mul(filippoCofactorScalar, p) // multiply by cofactor
			if p.Equal(&filippoNullPoint) {
				continue // unlucky; try again
			}
			return p // success
		}

		// Since we need the point's y-coordinate to hold our data,
		// we must simply check if the point is in the subgroup
		// and retry point generation until it is.
		var Q Point
		Q.Mul(filippoPrimeOrderScalar, p)
		if Q.Equal(&filippoNullPoint) {
			return p // success
		}
		// Keep trying...
	}
}

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
	return marshalling.PointMarshalTo(p, w)
}

func (p *Point) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}
