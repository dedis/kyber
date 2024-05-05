package test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
)

// Suite represents the functionalities that this package can test
type suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

type suiteStable struct {
	suite
	xof kyber.XOF
}

func newSuiteStable(s suite) *suiteStable {
	return &suiteStable{
		suite: s,
		xof:   s.XOF(nil),
	}
}

func (ss *suiteStable) RandomStream() cipher.Stream {
	return ss.xof
}

func testEmbed(t *testing.T, g kyber.Group, rand cipher.Stream, points *[]kyber.Point,
	s string) {
	// println("embedding: ", s)
	b := []byte(s)

	p := g.Point().Embed(b, rand)
	x, err := p.Data()
	if err != nil {
		t.Errorf("Point extraction failed for %v: %v", p, err)
	}
	//println("extracted data (", len(x), " bytes): ", string(x))
	//println("EmbedLen(): ", g.Point().EmbedLen())
	max := g.Point().EmbedLen()
	if max > len(b) {
		max = len(b)
	}
	if !bytes.Equal(append(x, b[max:]...), b) {
		t.Errorf("Point embedding corrupted the data")
	}

	*points = append(*points, p)
}

func testPointSet(t *testing.T, g kyber.Group, rand cipher.Stream) {
	N := 1000
	null := g.Point().Null()
	for i := 0; i < N; i++ {
		P1 := g.Point().Pick(rand)
		P2 := g.Point()
		P2.Set(P1)
		if !P1.Equal(P2) {
			t.Errorf("Set() set to a different point: %v != %v", P1, P2)
		}
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			if P1.Equal(P2) {
				t.Errorf("Modifying P1 shouldn't modify P2: %v == %v", P1, P2)
			}
		}
	}
}

func testPointClone(t *testing.T, g kyber.Group, rand cipher.Stream) {
	N := 1000
	null := g.Point().Null()
	for i := 0; i < N; i++ {
		P1 := g.Point().Pick(rand)
		P2 := P1.Clone()
		if !P1.Equal(P2) {
			t.Errorf("Clone didn't work for point: %v != %v", P1, P2)
		}
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			if P1.Equal(P2) {
				t.Errorf("Modifying P1 shouldn't modify P2: %v == %v", P1, P2)
			}
		}
	}
}

func testScalarSet(t *testing.T, g kyber.Group, rand cipher.Stream) {
	N := 1000
	zero := g.Scalar().Zero()
	one := g.Scalar().One()
	for i := 0; i < N; i++ {
		s1 := g.Scalar().Pick(rand)
		s2 := g.Scalar().Set(s1)
		if !s1.Equal(s2) {
			t.Errorf("Set() set to a different scalar: %v != %v", s1, s2)
		}
		if !s1.Equal(zero) && !s1.Equal(one) {
			s1.Mul(s1, s1)
			if s1.Equal(s2) {
				t.Errorf("Modifying s1 shouldn't modify s2: %v == %v", s1, s2)
			}
		}
	}
}

func testScalarClone(t *testing.T, g kyber.Group, rand cipher.Stream) {
	N := 1000
	zero := g.Scalar().Zero()
	one := g.Scalar().One()
	for i := 0; i < N; i++ {
		s1 := g.Scalar().Pick(rand)
		s2 := s1.Clone()
		if !s1.Equal(s2) {
			t.Errorf("Clone didn't work for scalar: %v != %v", s1, s2)
		}
		if !s1.Equal(zero) && !s1.Equal(one) {
			s1.Mul(s1, s1)
			if s1.Equal(s2) {
				t.Errorf("Modifying s1 shouldn't modify s2: %v == %v", s1, s2)
			}
		}
	}
}

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
		t.Errorf("first secret is scalar zero %v", s1)
	}
	if s2.Equal(szero) {
		t.Errorf("second secret is scalar zero %v", s2)
	}
	if s1.Equal(s2) {
		t.Errorf("not getting unique secrets: picked %s twice", s1)
	}

	gen := g.Point().Base()
	points = append(points, gen)

	// Sanity-check relationship between addition and multiplication
	p1 := g.Point().Add(gen, gen)
	p2 := g.Point().Mul(stmp.SetInt64(2), nil)
	if !p1.Equal(p2) {
		t.Errorf("multiply by two doesn't work: %v == %v (+) %[2]v != %[2]v (x) 2 == %v", p1, gen, p2)
	}
	p1.Add(p1, p1)
	p2.Mul(stmp.SetInt64(4), nil)
	if !p1.Equal(p2) {
		t.Errorf("multiply by four doesn't work: %v (+) %[1]v != %v (x) 4 == %v",
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
	ptmp.Mul(stmp.SetInt64(-1), nil).Add(ptmp, gen)
	if !ptmp.Equal(pzero) {
		t.Errorf("generator additive identity doesn't work: %v (x) -1 (+) %v != %v the group point identity",
			ptmp.Mul(stmp.SetInt64(-1), nil), gen, pzero)
	}
	// secret.Inv works only in prime-order groups
	if primeOrder {
		ptmp.Mul(stmp.SetInt64(2), nil).Mul(stmp.Inv(stmp), ptmp)
		if !ptmp.Equal(gen) {
			t.Errorf("generator multiplicative identity doesn't work:\n%v (x) %v = %v\n%[3]v (x) %v = %v",
				ptmp.Base().String(), stmp.SetInt64(2).String(),
				ptmp.Mul(stmp.SetInt64(2), nil).String(),
				stmp.Inv(stmp).String(),
				ptmp.Mul(stmp.SetInt64(2), nil).Mul(stmp.Inv(stmp), ptmp).String())
		}
	}

	p1.Mul(s1, gen)
	p2.Mul(s2, gen)
	if p1.Equal(p2) {
		t.Errorf("encryption isn't producing unique points: %v (x) %v == %v (x) %[2]v == %[4]v", s1, gen, s2, p1)
	}
	points = append(points, p1)

	dh1 := g.Point().Mul(s2, p1)
	dh2 := g.Point().Mul(s1, p2)
	if !dh1.Equal(dh2) {
		t.Errorf("Diffie-Hellman didn't work: %v == %v (x) %v != %v (x) %v == %v", dh1, s2, p1, s1, p2, dh2)
	}
	points = append(points, dh1)
	t.Logf("shared secret = %v", dh1)

	// Test secret inverse to get from dh1 back to p1
	if primeOrder {
		ptmp.Mul(g.Scalar().Inv(s2), dh1)
		if !ptmp.Equal(p1) {
			t.Errorf("Scalar inverse didn't work: %v != (-)%v (x) %v == %v", p1, s2, dh1, ptmp)
		}
	}

	// Zero and One identity secrets
	//println("dh1^0 = ",ptmp.Mul(dh1, szero).String())
	if !ptmp.Mul(szero, dh1).Equal(pzero) {
		t.Errorf("Encryption with secret=0 didn't work: %v (x) %v == %v != %v", szero, dh1, ptmp, pzero)
	}
	if !ptmp.Mul(sone, dh1).Equal(dh1) {
		t.Errorf("Encryption with secret=1 didn't work: %v (x) %v == %v != %[2]v", sone, dh1, ptmp)
	}

	// Additive homomorphic identities
	ptmp.Add(p1, p2)
	stmp.Add(s1, s2)
	pt2 := g.Point().Mul(stmp, gen)
	if !pt2.Equal(ptmp) {
		t.Errorf("Additive homomorphism doesn't work: %v + %v == %v, %[3]v (x) %v == %v != %v == %v (+) %v",
			s1, s2, stmp, gen, pt2, ptmp, p1, p2)
	}
	ptmp.Sub(p1, p2)
	stmp.Sub(s1, s2)
	pt2.Mul(stmp, gen)
	if !pt2.Equal(ptmp) {
		t.Errorf("Additive homomorphism doesn't work: %v - %v == %v, %[3]v (x) %v == %v != %v == %v (-) %v",
			s1, s2, stmp, gen, pt2, ptmp, p1, p2)
	}
	st2 := g.Scalar().Neg(s2)
	st2.Add(s1, st2)
	if !stmp.Equal(st2) {
		t.Errorf("Scalar.Neg doesn't work: -%v == %v, %[2]v + %v == %v != %v",
			s2, g.Scalar().Neg(s2), s1, st2, stmp)
	}
	pt2.Neg(p2).Add(pt2, p1)
	if !pt2.Equal(ptmp) {
		t.Errorf("Point.Neg doesn't work: (-)%v == %v, %[2]v (+) %v == %v != %v",
			p2, g.Point().Neg(p2), p1, pt2, ptmp)
	}

	// Multiplicative homomorphic identities
	stmp.Mul(s1, s2)
	if !ptmp.Mul(stmp, gen).Equal(dh1) {
		t.Errorf("Multiplicative homomorphism doesn't work: %v * %v == %v, %[2]v (x) %v == %v != %v",
			s1, s2, stmp, gen, ptmp, dh1)
	}
	if primeOrder {
		st2.Inv(s2)
		st2.Mul(st2, stmp)
		if !st2.Equal(s1) {
			t.Errorf("Scalar division doesn't work: %v^-1 * %v == %v * %[2]v == %[4]v != %v",
				s2, stmp, g.Scalar().Inv(s2), st2, s1)
		}
		st2.Div(stmp, s2)
		if !st2.Equal(s1) {
			t.Errorf("Scalar division doesn't work: %v / %v == %v != %v",
				stmp, s2, st2, s1)
		}
	}

	// Test randomly picked points
	last := gen
	for i := 0; i < 5; i++ {
		rgen := g.Point().Pick(rand)
		if rgen.Equal(last) {
			t.Errorf("Pick() not producing unique points: got %v twice", rgen)
		}
		last = rgen

		ptmp.Mul(stmp.SetInt64(-1), rgen).Add(ptmp, rgen)
		if !ptmp.Equal(pzero) {
			t.Errorf("random generator fails additive identity: %v (x) %v == %v, %v (+) %[3]v == %[5]v != %v",
				g.Scalar().SetInt64(-1), rgen, g.Point().Mul(g.Scalar().SetInt64(-1), rgen),
				rgen, g.Point().Mul(g.Scalar().SetInt64(-1), rgen), pzero)
		}
		if primeOrder {
			ptmp.Mul(stmp.SetInt64(2), rgen).Mul(stmp.Inv(stmp), ptmp)
			if !ptmp.Equal(rgen) {
				t.Errorf("random generator fails multiplicative identity: %v (x) (2 (x) %v) == %v != %[2]v",
					stmp, rgen, ptmp)
			}
		}
		points = append(points, rgen)
	}

	// Test embedding data
	testEmbed(t, g, rand, &points, "Hi!")
	testEmbed(t, g, rand, &points, "The quick brown fox jumps over the lazy dog")

	// Test verifiable secret sharing

	// Test encoding and decoding
	buf := new(bytes.Buffer)
	for i := 0; i < 5; i++ {
		buf.Reset()
		s := g.Scalar().Pick(rand)
		if _, err := s.MarshalTo(buf); err != nil {
			t.Errorf("encoding of secret fails: " + err.Error())
		}
		if _, err := stmp.UnmarshalFrom(buf); err != nil {
			t.Errorf("decoding of secret fails: " + err.Error())
		}
		if !stmp.Equal(s) {
			t.Errorf("decoding produces different secret than encoded")
		}

		buf.Reset()
		p := g.Point().Pick(rand)
		if _, err := p.MarshalTo(buf); err != nil {
			t.Errorf("encoding of point fails: " + err.Error())
		}
		if _, err := ptmp.UnmarshalFrom(buf); err != nil {
			t.Errorf("decoding of point fails: " + err.Error())
		}
		if !ptmp.Equal(p) {
			t.Errorf("decoding produces different point than encoded")
		}
	}

	// Test that we can marshal/ unmarshal null point
	pzero = g.Point().Null()
	b, _ := pzero.MarshalBinary()
	repzero := g.Point()
	err := repzero.UnmarshalBinary(b)
	if err != nil {
		t.Errorf("Could not unmarshall binary %v: %v", b, err)
	}

	testPointSet(t, g, rand)
	testPointClone(t, g, rand)
	testScalarSet(t, g, rand)
	testScalarClone(t, g, rand)

	return points
}

// GroupTest applies a generic set of validation tests to a cryptographic Group.
func GroupTest(t *testing.T, g kyber.Group) {
	testGroup(t, g, random.New())
}

// CompareGroups tests two group implementations that are supposed to be equivalent,
// and compare their results.
func CompareGroups(t *testing.T, fn func(key []byte) kyber.XOF, g1, g2 kyber.Group) {

	// Produce test results from the same pseudorandom seed
	r1 := testGroup(t, g1, fn(nil))
	r2 := testGroup(t, g2, fn(nil))

	// Compare resulting Points
	for i := range r1 {
		b1, _ := r1[i].MarshalBinary()
		b2, _ := r2[i].MarshalBinary()
		if !bytes.Equal(b1, b2) {
			t.Errorf("unequal result-pair %v\n1: %v\n2: %v",
				i, r1[i], r2[i])
		}
	}
}

// SuiteTest tests a standard set of validation tests to a ciphersuite.
func SuiteTest(t *testing.T, suite suite) {

	// Try hashing something
	h := suite.Hash()
	l := h.Size()
	//println("HashLen: ", l)

	_, _ = h.Write([]byte("abc"))
	hb := h.Sum(nil)
	//println("Hash:")
	//println(hex.Dump(hb))
	if h.Size() != l || len(hb) != l {
		t.Errorf("inconsistent hash output length: %v vs %v vs %v", l, h.Size(), len(hb))
	}

	// Generate some pseudorandom bits
	x := suite.XOF(hb)
	sb := make([]byte, 128)
	x.Read(sb)
	//fmt.Println("Stream:")
	//fmt.Println(hex.Dump(sb))

	// Test if it generates two fresh keys
	p1 := key.NewKeyPair(suite)
	p2 := key.NewKeyPair(suite)
	if p1.Private.Equal(p2.Private) {
		t.Errorf("NewKeyPair returns the same secret key twice: %v", p1)
	}

	// Test if it creates the same key with the same seed
	p1 = new(key.Pair)
	p2 = new(key.Pair)

	p1.Gen(newSuiteStable(suite))
	p2.Gen(newSuiteStable(suite))
	if !p1.Private.Equal(p2.Private) {
		t.Errorf("NewKeyPair returns different keys for same seed: %v != %v", p1, p2)
	}

	// Test the public-key group arithmetic
	GroupTest(t, suite)
}
