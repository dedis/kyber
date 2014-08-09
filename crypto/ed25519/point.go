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


type ed25519Point struct {
	ge ExtendedGroupElement
	//c *ed25519Curve
}

func (P *ed25519Point) String() string {
	var b [32]byte
	P.ge.ToBytes(&b)
	return hex.EncodeToString(b[:])
}

func (P *ed25519Point) Len() int {
	return 32
}

func (P *ed25519Point) Encode() []byte {
	var b [32]byte
	P.ge.ToBytes(&b)
	return b[:]
}

func (P *ed25519Point) Decode(b []byte) error {
	if !P.ge.FromBytes(b) {
		return errors.New("invalid Ed25519 curve point")
	}
	return nil
}

// Equality test for two Points on the same curve
func (P *ed25519Point) Equal(P2 crypto.Point) bool {

	// XXX better to test equality without normalizing extended coords

	var b1,b2 [32]byte
	P.ge.ToBytes(&b1)
	P2.(*ed25519Point).ge.ToBytes(&b2)
	for i := range(b1) {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

// Set point to be equal to P2.
func (P *ed25519Point) Set(P2 crypto.Point) crypto.Point {
	P.ge = P2.(*ed25519Point).ge
	return P
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *ed25519Point) Null() crypto.Point {
	P.ge.Zero()
	return P
}

// Set to the standard base point for this curve
func (P *ed25519Point) Base() crypto.Point {
	P.ge = baseext
	return P
}

func (P *ed25519Point) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (P *ed25519Point) Pick(data []byte,rand cipher.Stream) (crypto.Point, []byte) {
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
func (P *ed25519Point) Data() ([]byte,error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	dl := int(b[0])				// extract length byte
	if dl > P.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[1:1+dl],nil
}

func (P *ed25519Point) Add(P1,P2 crypto.Point) crypto.Point {
	E1 := P1.(*ed25519Point)
	E2 := P2.(*ed25519Point)

	var t2 CachedGroupElement
	var r CompletedGroupElement

	E2.ge.ToCached(&t2)
	geAdd(&r, &E1.ge, &t2)
	r.ToExtended(&P.ge)

	// XXX in this case better just to use general addition formula?

	return P
}

func (P *ed25519Point) Sub(P1,P2 crypto.Point) crypto.Point {
	E1 := P1.(*ed25519Point)
	E2 := P2.(*ed25519Point)

	var t2 CachedGroupElement
	var r CompletedGroupElement

	E2.ge.ToCached(&t2)
	geSub(&r, &E1.ge, &t2)
	r.ToExtended(&P.ge)

	// XXX in this case better just to use general addition formula?

	return P
}

// Find the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *ed25519Point) Neg(A crypto.Point) crypto.Point {
	panic("XXX")
}


// Multiply point p by scalar s using the repeated doubling method.
// XXX This is vartime; for our general-purpose Mul operator
// it would be far preferable for security to do this constant-time.
func (P *ed25519Point) Mul(AP crypto.Point, s crypto.Secret) crypto.Point {
	A := AP.(*ed25519Point)
	a := s.(*crypto.ModInt).V.Bytes()

	var aSlide [256]int8
	var Ai [8]CachedGroupElement // A,3A,5A,7A,9A,11A,13A,15A
	var t CompletedGroupElement
	var u, A2 ExtendedGroupElement
	var r ProjectiveGroupElement
	var i int

	// Slide through the secret exponent clumping sequences of bits,
	// resulting in only zero or odd multipliers between -15 and 15.
	slide(&aSlide, a, true)

	// Form an array of odd multiples of A from 1A through 15A,
	// in addition-ready cached group element form.
	// We only need odd multiples of A because slide()
	// produces only odd-multiple clumps of bits.
	A.ge.ToCached(&Ai[0])
	A.ge.Double(&t)
	t.ToExtended(&A2)
	for i := 0; i < 7; i++ {
		geAdd(&t, &A2, &Ai[i])
		t.ToExtended(&u)
		u.ToCached(&Ai[i+1])
	}

	// Process the multiplications from most-significant bit downward
	for i = 255; ; i-- {
		if i < 0 {		// no bits set
			P.ge.Zero()
			return P
		}
		if aSlide[i] != 0 {
			break
		}
	}

	// first (most-significant) nonzero clump of bits
	u.Zero()
	if aSlide[i] > 0 {
		geAdd(&t, &u, &Ai[aSlide[i]/2])
	} else if aSlide[i] < 0 {
		geSub(&t, &u, &Ai[(-aSlide[i])/2])
	}
	i--

	// remaining bits
	for ; i >= 0; i-- {
		t.ToProjective(&r)
		r.Double(&t)

		if aSlide[i] > 0 {
			t.ToExtended(&u)
			geAdd(&t, &u, &Ai[aSlide[i]/2])
		} else if aSlide[i] < 0 {
			t.ToExtended(&u)
			geSub(&t, &u, &Ai[(-aSlide[i])/2])
		}
	}

	t.ToExtended(&P.ge)
	return P
}



type ed25519Curve struct {
}

func (c *ed25519Curve) String() string {
	return "Ed25519"
}

func (c *ed25519Curve) SecretLen() int {
	return 32
}

func (c *ed25519Curve) Secret() crypto.Secret {
	return crypto.NewModInt(0, order)
}

func (c *ed25519Curve) PointLen() int {
	return 32
}

func (c *ed25519Curve) Point() crypto.Point {
	P := new(ed25519Point)
	//P.c = c
	return P
}


type suiteEd25519 struct {
	ed25519Curve
} 
// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) HashLen() int { return sha256.Size }
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suiteEd25519) KeyLen() int { return 16 }
func (s *suiteEd25519) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519() crypto.Suite {
	suite := new(suiteEd25519)
	return suite
}

