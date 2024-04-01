package circl_bls12381_test

import (
	"bytes"
	"crypto/cipher"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	this "go.dedis.ch/kyber/v3/pairing/circl_bls12381"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/sign/test"
	"go.dedis.ch/kyber/v3/util/random"
)

// Code extracted from kyber/utils/test
// TODO: expose API in forked drand/kyber
// Apply a generic set of validation tests to a cryptographic Group,
// using a given source of [pseudo-]randomness.
//
// Returns a log of the pseudorandom Points produced in the test,
// for comparison across alternative implementations
// that are supposed to be equivalent.
func testGroup(t *testing.T, g kyber.Group, rand cipher.Stream) []kyber.Point {
	t.Logf("\nTesting group '%s': %d-byte Point, %d-byte Scalar\n",
		g.String(), g.PointLen(), g.ScalarLen())

	points := make([]kyber.Point, 0)
	ptmp := g.Point()
	stmp := g.Scalar()
	pzero := g.Point().Null()
	szero := g.Scalar().Zero()
	sone := g.Scalar().One()

	// Do a simple Diffie-Hellman test
	s1 := g.Scalar().Pick(rand)
	s2 := g.Scalar().Pick(rand)
	if s1.Equal(szero) {
		t.Fatalf("first secret is scalar zero %v", s1)
	}
	if s2.Equal(szero) {
		t.Fatalf("second secret is scalar zero %v", s2)
	}
	if s1.Equal(s2) {
		t.Fatalf("not getting unique secrets: picked %s twice", s1)
	}

	gen := g.Point().Base()
	points = append(points, gen)

	// Sanity-check relationship between addition and multiplication
	p1 := g.Point().Add(gen, gen)
	p2 := g.Point().Mul(stmp.SetInt64(2), nil)
	if !p1.Equal(p2) {
		t.Fatalf("multiply by two doesn't work: %v == %v (+) %[2]v != %[2]v (x) 2 == %v", p1, gen, p2)
	}
	p1.Add(p1, p1)
	p2.Mul(stmp.SetInt64(4), nil)
	if !p1.Equal(p2) {
		t.Fatalf("multiply by four doesn't work: %v (+) %[1]v != %v (x) 4 == %v",
			g.Point().Add(gen, gen), gen, p2)
	}
	points = append(points, p1)

	// Find out if this curve has a prime order:
	// if the curve does not offer a method IsPrimeOrder,
	// then assume that it is.
	type canCheckPrimeOrder interface {
		IsPrimeOrder() bool
	}
	primeOrder := true
	if gpo, ok := g.(canCheckPrimeOrder); ok {
		primeOrder = gpo.IsPrimeOrder()
	}

	// Verify additive and multiplicative identities of the generator.
	// TODO: Check GT exp
	/*fmt.Println("Inverse of base")*/
	//f := ptmp.Base().(*KyberGT).f
	//newFp12(nil).inverse(f, f)
	//fmt.Printf("\n-Inverse: %v\n", f)
	//fmt.Println("Multiply by -1")
	ptmp.Mul(stmp.SetInt64(-1), nil).Add(ptmp, gen)
	/*fmt.Printf(" \n\nChecking equality additive identity\nptmp: %v \n\n zero %v\n", ptmp, pzero)*/
	if !ptmp.Equal(pzero) {
		t.Fatalf("generator additive identity doesn't work: (scalar -1 %v) %v (x) -1 (+) %v = %v != %v the group point identity",
			stmp.SetInt64(-1), ptmp.Mul(stmp.SetInt64(-1), nil), gen, ptmp.Mul(stmp.SetInt64(-1), nil).Add(ptmp, gen), pzero)
	}
	// secret.Inv works only in prime-order groups
	if primeOrder {
		ptmp.Mul(stmp.SetInt64(2), nil).Mul(stmp.Inv(stmp), ptmp)
		if !ptmp.Equal(gen) {
			t.Fatalf("generator multiplicative identity doesn't work:\n%v (x) %v = %v\n%[3]v (x) %v = %v",
				ptmp.Base().String(), stmp.SetInt64(2).String(),
				ptmp.Mul(stmp.SetInt64(2), nil).String(),
				stmp.Inv(stmp).String(),
				ptmp.Mul(stmp.SetInt64(2), nil).Mul(stmp.Inv(stmp), ptmp).String())
		}
	}

	p1.Mul(s1, gen)
	p2.Mul(s2, gen)
	if p1.Equal(p2) {
		t.Fatalf("encryption isn't producing unique points: %v (x) %v == %v (x) %[2]v == %[4]v", s1, gen, s2, p1)
	}
	points = append(points, p1)

	dh1 := g.Point().Mul(s2, p1)
	dh2 := g.Point().Mul(s1, p2)
	if !dh1.Equal(dh2) {
		t.Fatalf("Diffie-Hellman didn't work: %v == %v (x) %v != %v (x) %v == %v", dh1, s2, p1, s1, p2, dh2)
	}
	points = append(points, dh1)
	//t.Logf("shared secret = %v", dh1)

	// Test secret inverse to get from dh1 back to p1
	if primeOrder {
		ptmp.Mul(g.Scalar().Inv(s2), dh1)
		if !ptmp.Equal(p1) {
			t.Fatalf("Scalar inverse didn't work: %v != (-)%v (x) %v == %v", p1, s2, dh1, ptmp)
		}
	}

	// Zero and One identity secrets
	//println("dh1^0 = ",ptmp.Mul(dh1, szero).String())
	if !ptmp.Mul(szero, dh1).Equal(pzero) {
		t.Fatalf("Encryption with secret=0 didn't work: %v (x) %v == %v != %v", szero, dh1, ptmp, pzero)
	}
	if !ptmp.Mul(sone, dh1).Equal(dh1) {
		t.Fatalf("Encryption with secret=1 didn't work: %v (x) %v == %v != %[2]v", sone, dh1, ptmp)
	}

	// Additive homomorphic identities
	ptmp.Add(p1, p2)
	stmp.Add(s1, s2)
	pt2 := g.Point().Mul(stmp, gen)
	if !pt2.Equal(ptmp) {
		t.Fatalf("Additive homomorphism doesn't work: %v + %v == %v, %[3]v (x) %v == %v != %v == %v (+) %v",
			s1, s2, stmp, gen, pt2, ptmp, p1, p2)
	}
	ptmp.Sub(p1, p2)
	stmp.Sub(s1, s2)
	pt2.Mul(stmp, gen)
	if !pt2.Equal(ptmp) {
		t.Fatalf("Additive homomorphism doesn't work: %v - %v == %v, %[3]v (x) %v == %v != %v == %v (-) %v",
			s1, s2, stmp, gen, pt2, ptmp, p1, p2)
	}
	st2 := g.Scalar().Neg(s2)
	st2.Add(s1, st2)
	if !stmp.Equal(st2) {
		t.Fatalf("Scalar.Neg doesn't work: -%v == %v, %[2]v + %v == %v != %v",
			s2, g.Scalar().Neg(s2), s1, st2, stmp)
	}
	pt2.Neg(p2).Add(pt2, p1)
	if !pt2.Equal(ptmp) {
		t.Fatalf("Point.Neg doesn't work: (-)%v == %v, %[2]v (+) %v == %v != %v",
			p2, g.Point().Neg(p2), p1, pt2, ptmp)
	}

	// Multiplicative homomorphic identities
	stmp.Mul(s1, s2)
	if !ptmp.Mul(stmp, gen).Equal(dh1) {
		t.Fatalf("Multiplicative homomorphism doesn't work: %v * %v == %v, %[2]v (x) %v == %v != %v",
			s1, s2, stmp, gen, ptmp, dh1)
	}
	if primeOrder {
		st2.Inv(s2)
		st2.Mul(st2, stmp)
		if !st2.Equal(s1) {
			t.Fatalf("Scalar division doesn't work: %v^-1 * %v == %v * %[2]v == %[4]v != %v",
				s2, stmp, g.Scalar().Inv(s2), st2, s1)
		}
		st2.Div(stmp, s2)
		if !st2.Equal(s1) {
			t.Fatalf("Scalar division doesn't work: %v / %v == %v != %v",
				stmp, s2, st2, s1)
		}
	}

	pick := func(rand cipher.Stream) (p kyber.Point) {
		defer func() {
			/*if err := recover(); err != nil {*/
			//// TODO implement Pick for GT
			//p = g.Point().Mul(g.Scalar().Pick(rand), nil)
			//return
			/*}*/
		}()
		p = g.Point().Pick(rand)
		return
	}

	// Test randomly picked points
	last := gen
	for i := 0; i < 5; i++ {
		// TODO fork kyber and make that an interface
		rgen := pick(rand)
		if rgen.Equal(last) {
			t.Fatalf("Pick() not producing unique points: got %v twice", rgen)
		}
		last = rgen

		ptmp.Mul(stmp.SetInt64(-1), rgen).Add(ptmp, rgen)
		if !ptmp.Equal(pzero) {
			t.Fatalf("random generator fails additive identity: %v (x) %v == %v, %v (+) %[3]v == %[5]v != %v",
				g.Scalar().SetInt64(-1), rgen, g.Point().Mul(g.Scalar().SetInt64(-1), rgen),
				rgen, g.Point().Mul(g.Scalar().SetInt64(-1), rgen), pzero)
		}
		if primeOrder {
			ptmp.Mul(stmp.SetInt64(2), rgen).Mul(stmp.Inv(stmp), ptmp)
			if !ptmp.Equal(rgen) {
				t.Fatalf("random generator fails multiplicative identity: %v (x) (2 (x) %v) == %v != %[2]v",
					stmp, rgen, ptmp)
			}
		}
		points = append(points, rgen)
	}

	// Test encoding and decoding
	buf := new(bytes.Buffer)
	for i := 0; i < 5; i++ {
		buf.Reset()
		s := g.Scalar().Pick(rand)
		if _, err := s.MarshalTo(buf); err != nil {
			t.Fatalf("encoding of secret fails: " + err.Error())
		}
		if _, err := stmp.UnmarshalFrom(buf); err != nil {
			t.Fatalf("decoding of secret fails: " + err.Error())
		}
		if !stmp.Equal(s) {
			t.Fatalf("decoding produces different secret than encoded")
		}

		buf.Reset()
		p := pick(rand)
		if _, err := p.MarshalTo(buf); err != nil {
			t.Fatalf("encoding of point fails: " + err.Error())
		}
		if _, err := ptmp.UnmarshalFrom(buf); err != nil {
			t.Fatalf("decoding of point fails: " + err.Error())
		}

		if !ptmp.Equal(p) {
			t.Fatalf("decoding produces different point than encoded")
		}
	}

	// Test that we can marshal/ unmarshal null point
	pzero = g.Point().Null()
	b, _ := pzero.MarshalBinary()
	repzero := g.Point()
	err := repzero.UnmarshalBinary(b)
	if err != nil {
		t.Fatalf("Could not unmarshall binary %v: %v", b, err)
	}

	return points
}

// GroupTest applies a generic set of validation tests to a cryptographic Group.
func GroupTest(t *testing.T, g kyber.Group) {
	testGroup(t, g, random.New())
}

func TestKyberG1(t *testing.T) {
	GroupTest(t, this.G1)
}

func TestKyberG2(t *testing.T) {
	GroupTest(t, this.G2)
}

func TestKyberPairingG2(t *testing.T) {
	s := this.Suite{}
	a := s.G1().Scalar().Pick(s.RandomStream())
	b := s.G2().Scalar().Pick(s.RandomStream())
	aG := s.G1().Point().Mul(a, nil)
	bH := s.G2().Point().Mul(b, nil)
	ab := s.G1().Scalar().Mul(a, b)
	abG := s.G1().Point().Mul(ab, nil)
	// e(aG, bG) = e(G,H)^(ab)
	p1 := s.Pair(aG, bH)
	// e((ab)G,H) = e(G,H)^(ab)
	p2 := s.Pair(abG, s.G2().Point().Base())
	require.True(t, p1.Equal(p2))
	require.True(t, s.ValidatePairing(aG, bH, abG.Clone(), s.G2().Point().Base()))

	pRandom := s.Pair(aG, s.G2().Point().Pick(s.RandomStream()))
	require.False(t, p1.Equal(pRandom))
	pRandom = s.Pair(s.G1().Point().Pick(s.RandomStream()), bH)
	require.False(t, p1.Equal(pRandom))
}

func TestRacePairings(t *testing.T) {
	s := this.Suite{}
	a := s.G1().Scalar().Pick(s.RandomStream())
	aG := s.G1().Point().Mul(a, nil)
	B := s.G2().Point().Pick(s.RandomStream())
	aB := s.G2().Point().Mul(a, B.Clone())
	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			//  e(p1,p2) =?= e(inv1^-1, inv2^-1)
			s.ValidatePairing(aG, B, s.G1().Point(), aB)
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkPairingSeparate(bb *testing.B) {
	s := this.Suite{}
	a := s.G1().Scalar().Pick(s.RandomStream())
	b := s.G2().Scalar().Pick(s.RandomStream())
	aG := s.G1().Point().Mul(a, nil)
	bH := s.G2().Point().Mul(b, nil)
	ab := s.G1().Scalar().Mul(a, b)
	abG := s.G1().Point().Mul(ab, nil)
	bb.ResetTimer()
	for i := 0; i < bb.N; i++ {

		// e(aG, bG) = e(G,H)^(ab)
		p1 := s.Pair(aG, bH)
		// e((ab)G,H) = e(G,H)^(ab)
		p2 := s.Pair(abG, s.G2().Point().Base())
		if !p1.Equal(p2) {
			panic("aie")
		}
	}
}

func BenchmarkPairingInv(bb *testing.B) {
	s := this.Suite{}
	a := s.G1().Scalar().Pick(s.RandomStream())
	b := s.G2().Scalar().Pick(s.RandomStream())
	aG := s.G1().Point().Mul(a, nil)
	bH := s.G2().Point().Mul(b, nil)
	ab := s.G1().Scalar().Mul(a, b)
	abG := s.G1().Point().Mul(ab, nil)
	bb.ResetTimer()
	for i := 0; i < bb.N; i++ {
		if !s.ValidatePairing(aG, bH, abG.Clone(), s.G2().Point().Base()) {
			panic("aie")
		}
	}
}

func TestKyberBLSG2(t *testing.T) {
	suite := this.Suite{}
	scheme := bls.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}

func TestKyberBLSG1(t *testing.T) {
	suite := this.Suite{}
	scheme := bls.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}

func TestKyberThresholdG2(t *testing.T) {
	suite := this.Suite{}
	tscheme := tbls.NewThresholdSchemeOnG2(suite)
	test.ThresholdTest(t, suite.G1(), tscheme)
}

func TestKyberThresholdG1(t *testing.T) {
	suite := this.Suite{}
	tscheme := tbls.NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), tscheme)
}

func TestIsValidGroup(t *testing.T) {
	suite := this.Suite{}
	p1 := suite.G1().Point().Pick(random.New())
	p2 := suite.G1().Point().Pick(random.New())

	require.True(t, p1.(kyber.SubGroupElement).IsInCorrectGroup())
	require.True(t, p2.(kyber.SubGroupElement).IsInCorrectGroup())
}

var suite = this.Suite{}

func NewElement() kyber.Scalar {
	return suite.G1().Scalar()
}
func NewG1() kyber.Point {
	return suite.G1().Point().Base()
}
func NewG2() kyber.Point {
	return suite.G2().Point().Base()
}
func Pair(a, b kyber.Point) kyber.Point {
	return suite.Pair(a, b)
}
func TestBasicPairing(t *testing.T) {

	// we test a * b = c + d
	a := NewElement().Pick(random.New())
	b := NewElement().Pick(random.New())
	c := NewElement().Pick(random.New())
	d := NewElement().Sub(NewElement().Mul(a, b), c)

	// check in the clear
	ab := NewElement().Mul(a, b)
	cd := NewElement().Add(c, d)
	require.True(t, ab.Equal(cd))

	// check in the exponent now with the following
	// e(aG1,bG2) = e(cG1,G2) * e(G1,dG2) <=>
	// e(G1,G2)^(a*b) = e(G1,G2)^c * e(G1,G2)^d
	// e(G1,G2)^(a*b) = e(G1,G2)^(c + d)
	aG := NewG1().Mul(a, nil)
	bG := NewG2().Mul(b, nil)
	left := Pair(aG, bG)

	cG := NewG1().Mul(c, nil)
	right1 := Pair(cG, NewG2())
	dG := NewG2().Mul(d, nil)
	right2 := Pair(NewG1(), dG)
	right := suite.GT().Point().Add(right1, right2)
	require.True(t, left.Equal(right))

	// Test if addition works in GT
	mright := right.Clone().Neg(right)
	res := mright.Add(mright, right)
	require.True(t, res.Equal(suite.GT().Point().Null()))

	// Test if Sub works in GT
	expZero := right.Clone().Sub(right, right)
	require.True(t, expZero.Equal(suite.GT().Point().Null()))

	//  Test if scalar mul works in GT
	// e(aG,G) == e(G,G)^a
	left = Pair(aG, suite.G2().Point().Base())
	right = Pair(suite.G1().Point().Base(), suite.G2().Point().Base())
	right = right.Mul(a, right)
	require.True(t, left.Equal(right))
}
