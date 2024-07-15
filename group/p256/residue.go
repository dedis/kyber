package p256

import (
	"crypto/cipher"
	"crypto/dsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/util/random"
)

var one = big.NewInt(1)
var two = big.NewInt(2)

type residuePoint struct {
	big.Int
	g *ResidueGroup
}

// Steal value from DSA, which uses recommendation from FIPS 186-3
const numMRTests = 64

// Probabilistically test whether a big integer is prime.
func isPrime(i *big.Int) bool {
	return i.ProbablyPrime(numMRTests)
}

func (P *residuePoint) String() string { return P.Int.String() }

func (P *residuePoint) Equal(p2 kyber.Point) bool {
	return P.Int.Cmp(&p2.(*residuePoint).Int) == 0
}

func (P *residuePoint) Null() kyber.Point {
	P.Int.SetInt64(1)
	return P
}

func (P *residuePoint) Base() kyber.Point {
	P.Int.Set(P.g.G)
	return P
}

func (P *residuePoint) Set(P2 kyber.Point) kyber.Point {
	P.g = P2.(*residuePoint).g
	P.Int = P2.(*residuePoint).Int
	return P
}

func (P *residuePoint) Clone() kyber.Point {
	return &residuePoint{g: P.g, Int: P.Int}
}

func (P *residuePoint) Valid() bool {
	return P.Int.Sign() > 0 && P.Int.Cmp(P.g.P) < 0 &&
		new(big.Int).Exp(&P.Int, P.g.Q, P.g.P).Cmp(one) == 0
}

func (P *residuePoint) EmbedLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 16 bits for embedded data length.
	return (P.g.P.BitLen() - 8 - 16) / 8
}

func (P *residuePoint) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Embed the given data with some pseudo-random bits.
// This will only work efficiently for quadratic residue groups!
func (P *residuePoint) Embed(data []byte, rand cipher.Stream) kyber.Point {

	l := P.g.PointLen()
	dl := P.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(P.g.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl) // Encode length in low 16 bits
			b[l-2] = byte(dl >> 8)
			copy(b[l-dl-2:l-2], data) // Copy in embedded data
		}
		P.Int.SetBytes(b)
		if P.Valid() {
			return P
		}
	}
}

// Extract embedded data from a Residue group element
func (P *residuePoint) Data() ([]byte, error) {
	b := P.Int.Bytes()
	l := P.g.PointLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-2])<<8 + int(b[l-1])
	if dl > P.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-2 : l-2], nil
}

func (P *residuePoint) Add(A, B kyber.Point) kyber.Point {
	P.Int.Mul(&A.(*residuePoint).Int, &B.(*residuePoint).Int)
	P.Int.Mod(&P.Int, P.g.P)
	return P
}

func (P *residuePoint) Sub(A, B kyber.Point) kyber.Point {
	binv := new(big.Int).ModInverse(&B.(*residuePoint).Int, P.g.P)
	P.Int.Mul(&A.(*residuePoint).Int, binv)
	P.Int.Mod(&P.Int, P.g.P)
	return P
}

func (P *residuePoint) Neg(A kyber.Point) kyber.Point {
	P.Int.ModInverse(&A.(*residuePoint).Int, P.g.P)
	return P
}

func (P *residuePoint) Mul(s kyber.Scalar, B kyber.Point) kyber.Point {
	if B == nil {
		return P.Base().Mul(s, P)
	}
	// to protect against golang/go#22830
	var tmp big.Int
	tmp.Exp(&B.(*residuePoint).Int, &s.(*mod.Int).V, P.g.P)
	P.Int = tmp
	return P
}

func (P *residuePoint) MarshalSize() int {
	return (P.g.P.BitLen() + 7) / 8
}

func (P *residuePoint) MarshalBinary() ([]byte, error) {
	b := P.Int.Bytes() // may be shorter than len(buf)
	if pre := P.MarshalSize() - len(b); pre != 0 {
		return append(make([]byte, pre), b...), nil
	}
	return b, nil
}

func (P *residuePoint) UnmarshalBinary(data []byte) error {
	P.Int.SetBytes(data)
	if !P.Valid() {
		return errors.New("invalid Residue group element")
	}
	return nil
}

func (P *residuePoint) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(P, w)
}

func (P *residuePoint) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

/*
A ResidueGroup represents a DSA-style modular integer arithmetic group,
defined by two primes P and Q and an integer R, such that P = Q*R+1.
Points in a ResidueGroup are R-residues modulo P,
and Scalars are integer exponents modulo the group order Q.

In traditional DSA groups P is typically much larger than Q,
and hence use a large multiple R.
This is done to minimize the computational cost of modular exponentiation
while maximizing security against known classes of attacks:
P must be on the order of thousands of bits long
while for security Q is believed to require only hundreds of bits.
Such computation-optimized groups are suitable
for Diffie-Hellman agreement, DSA or ElGamal signatures, etc.,
which depend on Point.Mul() and homomorphic properties.

However, residue groups with large R are less suitable for
public-key cryptographic techniques that require choosing Points
pseudo-randomly or to contain embedded data,
as required by ElGamal encryption for example.
For such purposes quadratic residue groups are more suitable -
representing the special case where R=2 and hence P=2Q+1.
As a result, the Point.Pick() method should be expected to work efficiently
ONLY on quadratic residue groups in which R=2.
*/
type ResidueGroup struct {
	dsa.Parameters
	R *big.Int
}

func (g *ResidueGroup) String() string {
	return fmt.Sprintf("Residue%d", g.P.BitLen())
}

// ScalarLen returns the number of bytes in the encoding of a Scalar
// for this Residue group.
func (g *ResidueGroup) ScalarLen() int { return (g.Q.BitLen() + 7) / 8 }

// Scalar creates a Scalar associated with this Residue group,
// with an initial value of nil.
func (g *ResidueGroup) Scalar() kyber.Scalar {
	return mod.NewInt64(0, g.Q)
}

// PointLen returns the number of bytes in the encoding of a Point
// for this Residue group.
func (g *ResidueGroup) PointLen() int { return (g.P.BitLen() + 7) / 8 }

// Point creates a Point associated with this Residue group,
// with an initial value of nil.
func (g *ResidueGroup) Point() kyber.Point {
	p := new(residuePoint)
	p.g = g
	return p
}

// Order returns the order of this Residue group, namely the prime Q.
func (g *ResidueGroup) Order() *big.Int {
	return g.Q
}

// Valid validates the parameters for a Residue group,
// checking that P and Q are prime, P=Q*R+1,
// and that G is a valid generator for this group.
func (g *ResidueGroup) Valid() bool {

	// Make sure both P and Q are prime
	if !isPrime(g.P) || !isPrime(g.Q) {
		return false
	}

	// Validate the equation P = QR+1
	n := new(big.Int)
	n.Mul(g.Q, g.R)
	n.Add(n, one)
	if n.Cmp(g.P) != 0 {
		return false
	}

	// Validate the generator G
	if g.G.Cmp(one) <= 0 || n.Exp(g.G, g.Q, g.P).Cmp(one) != 0 {
		return false
	}

	return true
}

// SetParams explicitly initializes a ResidueGroup with given parameters.
func (g *ResidueGroup) SetParams(p, q, r, g1 *big.Int) {
	g.P = p
	g.Q = q
	g.R = r
	g.G = g1
	if !g.Valid() {
		panic("SetParams: bad Residue group parameters")
	}
}

// QuadraticResidueGroup initializes Residue group parameters for a quadratic residue group,
// by picking primes P and Q such that P=2Q+1
// and the smallest valid generator G for this group.
func (g *ResidueGroup) QuadraticResidueGroup(bitlen uint, rand cipher.Stream) {
	g.R = two

	// pick primes p,q such that p = 2q+1
	for i := 0; ; i++ {
		if i > 1000 {
			i = 0
		}

		// First pick a prime Q
		b := random.Bits(bitlen-1, true, rand)
		b[len(b)-1] |= 1 // must be odd
		g.Q = new(big.Int).SetBytes(b)
		if !isPrime(g.Q) {
			continue
		}

		// TODO:Does the corresponding P come out prime too?
		g.P = new(big.Int)
		g.P.Mul(g.Q, two)
		g.P.Add(g.P, one)
		if uint(g.P.BitLen()) == bitlen && isPrime(g.P) {
			break
		}
	}

	// pick standard generator G
	h := new(big.Int).Set(two)
	g.G = new(big.Int)
	for {
		g.G.Exp(h, two, g.P)
		if g.G.Cmp(one) != 0 {
			break
		}
		h.Add(h, one)
	}
}
