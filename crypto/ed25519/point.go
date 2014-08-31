package ed25519

import (
	//"fmt"
	"hash"
	"errors"
	"crypto/aes"
	"encoding/hex"
	"crypto/cipher"
	"crypto/sha256"
	"dissent/crypto"
)


type point struct {
	ge extendedGroupElement
	//c *curve
}

func (P *point) String() string {
	var b [32]byte
	P.ge.ToBytes(&b)
	return hex.EncodeToString(b[:])
}

func (P *point) Len() int {
	return 32
}

func (P *point) Encode() []byte {
	var b [32]byte
	P.ge.ToBytes(&b)
	return b[:]
}

func (P *point) Decode(b []byte) error {
	if !P.ge.FromBytes(b) {
		return errors.New("invalid Ed25519 curve point")
	}
	return nil
}

// Equality test for two Points on the same curve
func (P *point) Equal(P2 crypto.Point) bool {

	// XXX better to test equality without normalizing extended coords

	var b1,b2 [32]byte
	P.ge.ToBytes(&b1)
	P2.(*point).ge.ToBytes(&b2)
	for i := range(b1) {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

// Set point to be equal to P2.
func (P *point) Set(P2 crypto.Point) crypto.Point {
	P.ge = P2.(*point).ge
	return P
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *point) Null() crypto.Point {
	P.ge.Zero()
	return P
}

// Set to the standard base point for this curve
func (P *point) Base() crypto.Point {
	P.ge = baseext
	return P
}

func (P *point) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (P *point) Pick(data []byte, rand cipher.Stream) (crypto.Point, []byte) {
	// How many bytes to embed?
	dl := P.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		// Pick a random point, with optional embedded data
		var b [32]byte
		rand.XORKeyStream(b[:],b[:])
		if data != nil {
			b[0] = byte(dl)		// Encode length in low 8 bits
			copy(b[1:1+dl],data)	// Copy in data to embed
		}
		if P.ge.FromBytes(b[:]) {	// Try to decode
			return P,data[dl:]	// success
		}
		// invalid point, retry
	}
}

// Extract embedded data from a point group element
func (P *point) Data() ([]byte,error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	dl := int(b[0])				// extract length byte
	if dl > P.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[1:1+dl],nil
}

func (P *point) Add(P1,P2 crypto.Point) crypto.Point {
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

func (P *point) Sub(P1,P2 crypto.Point) crypto.Point {
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
func (P *point) Neg(A crypto.Point) crypto.Point {
	P.ge.Neg(&A.(*point).ge)
	return P
}


// Multiply point p by scalar s using the repeated doubling method.
// XXX This is vartime; for our general-purpose Mul operator
// it would be far preferable for security to do this constant-time.
func (P *point) Mul(A crypto.Point, s crypto.Secret) crypto.Point {

	// Convert the scalar to fixed-length little-endian form.
	sb := s.(*crypto.ModInt).V.Bytes()
	shi := len(sb)-1
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


type curve struct {
}

func (c *curve) String() string {
	return "Ed25519"
}

func (c *curve) SecretLen() int {
	return 32
}

func (c *curve) Secret() crypto.Secret {
	return crypto.NewModInt(0, order)
}

func (c *curve) PointLen() int {
	return 32
}

func (c *curve) Point() crypto.Point {
	P := new(point)
	//P.c = c
	return P
}


type suite struct {
	curve
} 
// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suite) HashLen() int { return sha256.Size }
func (s *suite) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suite) KeyLen() int { return 16 }
func (s *suite) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519() crypto.Suite {
	suite := new(suite)
	return suite
}

