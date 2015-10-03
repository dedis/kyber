package nist

import (
	"crypto/cipher"
	"crypto/dsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/random"
	"golang.org/x/net/context"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

type residueElement struct {
	big.Int
	g *ResidueGroup
}

// Steal value from DSA, which uses recommendation from FIPS 186-3
const numMRTests = 64

// Probabilistically test whether a big integer is prime.
func isPrime(i *big.Int) bool {
	return i.ProbablyPrime(numMRTests)
}

func (p *residueElement) String() string { return p.Int.String() }

func (p *residueElement) New() group.Element {
	return &residueElement{big.Int{}, p.g}
}

func (p *residueElement) Set(a group.Element) group.Element {
	ra := a.(*residueElement)
	p.Int.Set(&ra.Int)
	p.g = ra.g
	return p
}

func (p *residueElement) SetInt64(i int64) group.Element {
	p.Int.SetInt64(i)
	return p
}

func (p *residueElement) Equal(p2 group.Element) bool {
	return p.Int.Cmp(&p2.(*residueElement).Int) == 0
}

func (p *residueElement) Zero() group.Element {
	p.Int.SetInt64(1)
	return p
}

func (p *residueElement) One() group.Element {
	p.Int.Set(p.g.G)
	return p
}

func (p *residueElement) Valid() bool {
	return p.Int.Sign() > 0 && p.Int.Cmp(p.g.P) < 0 &&
		new(big.Int).Exp(&p.Int, p.g.Q, p.g.P).Cmp(one) == 0
}

func (p *residueElement) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 16 bits for embedded data length.
	return (p.g.P.BitLen() - 8 - 16) / 8
}

// Pick a point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
// This will only work efficiently for quadratic residue groups!
func (p *residueElement) Pick(data []byte, rand cipher.Stream) []byte {

	l := p.g.ElementLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(p.g.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl) // Encode length in low 16 bits
			b[l-2] = byte(dl >> 8)
			copy(b[l-dl-2:l-2], data) // Copy in embedded data
		}
		p.Int.SetBytes(b)
		if p.Valid() {
			return data[dl:]
		}
	}
}

// Extract embedded data from a Residue group element
func (p *residueElement) Data() ([]byte, error) {
	b := p.Int.Bytes()
	l := p.g.ElementLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-2])<<8 + int(b[l-1])
	if dl > p.PickLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-2 : l-2], nil
}

func (p *residueElement) Add(a, b group.Element) group.Element {
	p.Int.Mul(&a.(*residueElement).Int, &b.(*residueElement).Int)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *residueElement) Sub(a, b group.Element) group.Element {
	binv := new(big.Int).ModInverse(&b.(*residueElement).Int, p.g.P)
	p.Int.Mul(&a.(*residueElement).Int, binv)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *residueElement) Neg(a group.Element) group.Element {
	p.Int.ModInverse(&a.(*residueElement).Int, p.g.P)
	return p
}

func (p *residueElement) Mul(b, s group.Element) group.Element {
	if b == nil {
		p.One()
		b = p
	}
	p.Int.Exp(&b.(*residueElement).Int, &s.(*group.Int).V, p.g.P)
	return p
}

func (p *residueElement) MarshalSize() int {
	return (p.g.P.BitLen() + 7) / 8
}

func (p *residueElement) MarshalBinary() ([]byte, error) {
	b := p.Int.Bytes() // may be shorter than len(buf)
	if pre := p.MarshalSize() - len(b); pre != 0 {
		return append(make([]byte, pre), b...), nil
	}
	return b, nil
}

func (p *residueElement) UnmarshalBinary(data []byte) error {
	p.Int.SetBytes(data)
	if !p.Valid() {
		return errors.New("invalid Residue group element")
	}
	return nil
}

func (p *residueElement) Marshal(ctx context.Context, w io.Writer) (int, error) {
	return group.Marshal(ctx, p, w)
}

func (p *residueElement) Unmarshal(ctx context.Context, r io.Reader) (int, error) {
	return group.Unmarshal(ctx, p, r)
}

/*
A ResidueGroup represents a DSA-style modular integer arithmetic group,
defined by two primes P and Q and an integer R, such that P = Q*R+1.
Elements in a ResidueGroup are R-residues modulo P,
and Scalars are integer exponents modulo the group order Q.

In traditional DSA groups P is typically much larger than Q,
and hence use a large multiple R.
This is done to minimize the computational cost of modular exponentiation
while maximizing security against known classes of attacks:
P must be on the order of thousands of bits long
while for security Q is believed to require only hundreds of bits.
Such computation-optimized groups are suitable
for Diffie-Hellman agreement, DSA or ElGamal signatures, etc.,
which depend on Element.Mul() and homomorphic properties.

However, residue groups with large R are less suitable for
public-key cryptographic techniques that require choosing Elements
pseudo-randomly or to contain embedded data,
as required by ElGamal encryption for example, or by Dissent's
hash-generator construction for verifiable DC-nets.
For such purposes quadratic residue groups are more suitable -
representing the special case where R=2 and hence P=2Q+1.
As a result, the Element.Pick() method should be expected to work efficiently
ONLY on quadratic residue groups in which R=2.
*/
type ResidueGroup struct {
	dsa.Parameters
	R *big.Int
}

func (g *ResidueGroup) String() string {
	return fmt.Sprintf("Residue%d", g.P.BitLen())
}

func (g *ResidueGroup) PrimeOrder() bool {
	return true
}

// Return the number of bytes in the encoding of a Scalar
// for this Residue group.
func (g *ResidueGroup) ScalarLen() int { return (g.Q.BitLen() + 7) / 8 }

// Create a Scalar associated with this Residue group,
// with an initial value of nil.
func (g *ResidueGroup) Scalar() group.FieldElement {
	return group.NewInt(0, g.Q)
}

// Return the number of bytes in the encoding of a Element
// for this Residue group.
func (g *ResidueGroup) ElementLen() int { return (g.P.BitLen() + 7) / 8 }

// Create a Element associated with this Residue group,
// with an initial value of nil.
func (g *ResidueGroup) Element() group.Element {
	return &residueElement{big.Int{}, g}
}

// Returns the order of this Residue group, namely the prime Q.
func (g *ResidueGroup) Order() *big.Int {
	return g.Q
}

// Validate the parameters for a Residue group,
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

// Explicitly initialize a ResidueGroup with given parameters.
func (g *ResidueGroup) SetParams(P, Q, R, G *big.Int) {
	g.P = P
	g.Q = Q
	g.R = R
	g.G = G
	if !g.Valid() {
		panic("SetParams: bad Residue group parameters")
	}
}

// Initialize Residue group parameters for a quadratic residue group,
// by picking primes P and Q such that P=2Q+1
// and the smallest valid generator G for this group.
func (g *ResidueGroup) QuadraticResidueGroup(bitlen uint, rand cipher.Stream) {
	g.R = two

	// pick primes p,q such that p = 2q+1
	fmt.Printf("Generating %d-bit QR group", bitlen)
	for i := 0; ; i++ {
		if i > 1000 {
			print(".")
			i = 0
		}

		// First pick a prime Q
		b := random.Bits(bitlen-1, true, rand)
		b[len(b)-1] |= 1 // must be odd
		g.Q = new(big.Int).SetBytes(b)
		//println("q?",hex.EncodeToString(g.Q.Bytes()))
		if !isPrime(g.Q) {
			continue
		}

		// Does the corresponding P come out prime too?
		g.P = new(big.Int)
		g.P.Mul(g.Q, two)
		g.P.Add(g.P, one)
		//println("p?",hex.EncodeToString(g.P.Bytes()))
		if uint(g.P.BitLen()) == bitlen && isPrime(g.P) {
			break
		}
	}
	println()
	println("p", g.P.String())
	println("q", g.Q.String())

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
	println("g", g.G.String())
}

// Create a context configured with the given residue group.
func WithResidueGroup(parent abstract.Context, g *ResidueGroup) abstract.Context {
	return group.Context(parent, g)
}

// Create a context configured with a 512-bit prime residue group,
// for internal testing purposes.
// (This is not a big enough prime to be secure!!)
func withQR512(parent abstract.Context) abstract.Context {
	p, _ := new(big.Int).SetString("10198267722357351868598076141027380280417188309231803909918464305012113541414604537422741096561285049775792035177041672305646773132014126091142862443826263", 10)
	q, _ := new(big.Int).SetString("5099133861178675934299038070513690140208594154615901954959232152506056770707302268711370548280642524887896017588520836152823386566007063045571431221913131", 10)
	r := new(big.Int).SetInt64(2)
	g := new(big.Int).SetInt64(4)

	grp := &ResidueGroup{}
	grp.SetParams(p, q, r, g)

	return group.Context(parent, grp)
}
