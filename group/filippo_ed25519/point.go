package filippo_ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"
	"io"

	filippo_ed25519 "filippo.io/edwards25519"
)

var nullPoint = new(point).Null()

type point struct {
	ge extendedGroupElement
}

var marshalPointID = [8]byte{'e', 'd', '.', 'p', 'o', 'i', 'n', 't'}

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
		return errors.New("invalid Ed25519 curve point")
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
	b1, _ := P.MarshalBinary()
	b2, _ := P2.(*point).MarshalBinary()
	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
	fp2, _ := new(filippo_ed25519.Point).SetBytes(b2)
	return fp1.Equal(fp2) == 1
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

func (P *point) Base() kyber.Point {
	return nil
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
	return []byte{}, nil
}

//func (P *point) Add(P1, P2 kyber.Point) kyber.Point {
//	b1, _ := P1.(*point).MarshalBinary()
//	b2, _ := P2.(*point).MarshalBinary()
//	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
//	fp2, _ := new(filippo_ed25519.Point).SetBytes(b2)
//	ans := new(filippo_ed25519.Point).Add(fp1, fp2)
//	P.UnmarshalBinary(ans.Bytes())
//	return P
//}

//func (P *point) Sub(P1, P2 kyber.Point) kyber.Point {
//	b1, _ := P1.(*point).MarshalBinary()
//	b2, _ := P2.(*point).MarshalBinary()
//	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
//	fp2, _ := new(filippo_ed25519.Point).SetBytes(b2)
//	ans := new(filippo_ed25519.Point).Subtract(fp1, fp2)
//	P.UnmarshalBinary(ans.Bytes())
//	return P
//}

// Neg finds the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
//func (P *point) Neg(A kyber.Point) kyber.Point {
//	b1, _ := A.(*point).MarshalBinary()
//	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
//	fp1 = fp1.Negate(fp1)
//	P.UnmarshalBinary(fp1.Bytes())
//	return P
//}

//func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {
//
//	b2, _ := s.(*scalar).MarshalBinary()
//	fs, _ := new(filippo_ed25519.Scalar).SetCanonicalBytes(b2)
//
//	if A == nil {
//		ans := new(filippo_ed25519.Point).ScalarBaseMult(fs)
//		P.UnmarshalBinary(ans.Bytes())
//	} else {
//		b1, _ := A.(*point).MarshalBinary()
//		fp, _ := new(filippo_ed25519.Point).SetBytes(b1)
//		//ans := new(filippo_ed25519.Point).VarTimeMultiScalarMult([]*filippo_ed25519.Scalar{fs2}, []*filippo_ed25519.Point{fp1})
//		ans := new(filippo_ed25519.Point).ScalarMult(fs, fp)
//		P.UnmarshalBinary(ans.Bytes())
//	}
//	return P
//}

func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {
	//b1 := []byte{48, 189, 120, 52, 214, 153, 57, 176, 74, 4, 78, 97, 103, 85, 224, 99, 98, 78, 100, 216, 88, 14, 23, 222, 44, 61, 152, 82, 209, 243, 248, 188}
	b2 := []byte{100, 8, 188, 29, 221, 44, 54, 97, 129, 110, 7, 249, 145, 95, 32, 44, 67, 14, 73, 78, 28, 178, 136, 76, 125, 179, 228, 94, 104, 126, 124, 15}
	//fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
	fs2, _ := new(filippo_ed25519.Scalar).SetCanonicalBytes(b2)
	ans := new(filippo_ed25519.Point).ScalarBaseMult(fs2)
	_ = ans
	return nil
}

func (P *point) Add(P1, P2 kyber.Point) kyber.Point {
	b1 := []byte{167, 10, 92, 129, 31, 23, 10, 53, 34, 181, 164, 254, 101, 205, 20, 10, 184, 242, 223, 94, 198, 156, 188, 80, 225, 68, 64, 138, 149, 18, 167, 20}
	b2 := []byte{59, 209, 167, 90, 176, 41, 11, 248, 108, 1, 72, 130, 216, 87, 116, 102, 146, 170, 206, 228, 234, 247, 58, 78, 230, 181, 251, 218, 165, 110, 246, 176}
	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
	fp2, _ := new(filippo_ed25519.Point).SetBytes(b2)
	ans := new(filippo_ed25519.Point).Add(fp1, fp2)
	_ = ans
	return nil
}

func (P *point) Sub(P1, P2 kyber.Point) kyber.Point {
	b1 := []byte{167, 10, 92, 129, 31, 23, 10, 53, 34, 181, 164, 254, 101, 205, 20, 10, 184, 242, 223, 94, 198, 156, 188, 80, 225, 68, 64, 138, 149, 18, 167, 20}
	b2 := []byte{59, 209, 167, 90, 176, 41, 11, 248, 108, 1, 72, 130, 216, 87, 116, 102, 146, 170, 206, 228, 234, 247, 58, 78, 230, 181, 251, 218, 165, 110, 246, 176}
	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
	fp2, _ := new(filippo_ed25519.Point).SetBytes(b2)
	ans := new(filippo_ed25519.Point).Subtract(fp1, fp2)
	_ = ans
	return nil
}

func (P *point) Neg(P1 kyber.Point) kyber.Point {
	b1 := []byte{167, 10, 92, 129, 31, 23, 10, 53, 34, 181, 164, 254, 101, 205, 20, 10, 184, 242, 223, 94, 198, 156, 188, 80, 225, 68, 64, 138, 149, 18, 167, 20}
	fp1, _ := new(filippo_ed25519.Point).SetBytes(b1)
	fp1 = fp1.Negate(fp1)
	return nil
}
