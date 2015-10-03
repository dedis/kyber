package test

import (
	"bytes"
	"crypto/cipher"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
)

func testEmbed(suite *abstract.Suite, rand random.Stream,
	points *[]abstract.Point, s string) {

	//println("embedding: ",s)
	b := []byte(s)

	p, rem := suite.Point().Pick(b, rand)
	//println("embedded, remainder",len(rem),"/",len(b),":",string(rem))
	x, err := p.Data()
	if err != nil {
		panic("Point extraction failed: " + err.Error())
	}
	//println("extracted data: ",string(x))

	if !bytes.Equal(append(x, rem...), b) {
		panic("Point embedding corrupted the data")
	}

	*points = append(*points, p)
}

// Apply a generic set of validation tests to a cryptographic Group,
// using a given source of [pseudo-]randomness.
//
// Returns a log of the pseudorandom Points produced in the test,
// for comparison across alternative implementations
// that are supposed to be equivalent.
//
func testGroup(suite *abstract.Suite, rand cipher.Stream) []abstract.Point {
	//	fmt.Printf("\nTesting group '%s': %d-byte Point, %d-byte Secret\n",
	//			g.String(), suite.PointLen(), suite.ScalarLen())

	points := make([]abstract.Point, 0)
	ptmp := suite.Point()
	stmp := suite.Scalar()
	pzero := suite.Point().Null()
	szero := suite.Scalar().Zero()
	sone := suite.Scalar().One()

	// Do a simple Diffie-Hellman test
	s1 := suite.Scalar().Random(rand)
	s2 := suite.Scalar().Random(rand)
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	gen := suite.Point().Base()
	points = append(points, gen)

	// Verify additive and multiplicative identities of the generator.
	ptmp.BaseMul(stmp.SetInt64(-1)).Add(ptmp, gen)
	if !ptmp.Equal(pzero) {
		panic("oops, generator additive identity doesn't work")
	}
	if suite.Group().PrimeOrder() { // secret.Inv works only in prime-order groups
		ptmp.BaseMul(stmp.SetInt64(2)).Mul(ptmp, stmp.Inv(stmp))
		if !ptmp.Equal(gen) {
			panic("oops, generator multiplicative identity doesn't work")
		}
	}

	p1 := suite.Point().Mul(gen, s1)
	p2 := suite.Point().Mul(gen, s2)
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}
	points = append(points, p1)

	dh1 := suite.Point().Mul(p1, s2)
	dh2 := suite.Point().Mul(p2, s1)
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	points = append(points, dh1)
	//println("shared secret = ",dh1.String())

	// Test secret inverse to get from dh1 back to p1
	if suite.Group().PrimeOrder() {
		ptmp.Mul(dh1, suite.Scalar().Inv(s2))
		if !ptmp.Equal(p1) {
			panic("Secret inverse didn't work")
		}
	}

	// Zero and One identity secrets
	//println("dh1^0 = ",ptmp.Mul(dh1, szero).String())
	if !ptmp.Mul(dh1, szero).Equal(pzero) {
		panic("Encryption with secret=0 didn't work")
	}
	if !ptmp.Mul(dh1, sone).Equal(dh1) {
		panic("Encryption with secret=1 didn't work")
	}

	// Additive homomorphic identities
	ptmp.Add(p1, p2)
	stmp.Add(s1, s2)
	pt2 := suite.Point().Mul(gen, stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	ptmp.Sub(p1, p2)
	stmp.Sub(s1, s2)
	pt2.Mul(gen, stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	st2 := suite.Scalar().Neg(s2)
	st2.Add(s1, st2)
	if !stmp.Equal(st2) {
		panic("Secret.Neg doesn't work")
	}
	pt2.Neg(p2).Add(pt2, p1)
	if !pt2.Equal(ptmp) {
		panic("Point.Neg doesn't work")
	}

	// Multiplicative homomorphic identities
	stmp.Mul(s1, s2)
	if !ptmp.Mul(gen, stmp).Equal(dh1) {
		panic("Multiplicative homomorphism doesn't work")
	}
	if suite.Group().PrimeOrder() {
		st2.Inv(s2)
		st2.Mul(st2, stmp)
		if !st2.Equal(s1) {
			panic("Secret division doesn't work")
		}
		st2.Div(stmp, s2)
		if !st2.Equal(s1) {
			panic("Secret division doesn't work")
		}
	}

	// Test randomly picked points
	last := gen
	for i := 0; i < 5; i++ {
		rgen := suite.Point().Random(rand)
		if rgen.Equal(last) {
			panic("Pick() not producing unique points")
		}
		last = rgen

		ptmp.Mul(rgen, stmp.SetInt64(-1)).Add(ptmp, rgen)
		if !ptmp.Equal(pzero) {
			panic("random generator fails additive identity")
		}
		if suite.Group().PrimeOrder() {
			ptmp.Mul(rgen, stmp.SetInt64(2)).Mul(ptmp, stmp.Inv(stmp))
			if !ptmp.Equal(rgen) {
				panic("random generator fails multiplicative identity")
			}
		}
		points = append(points, rgen)
	}

	// Test embedding data
	testEmbed(suite, rand, &points, "Hi!")
	testEmbed(suite, rand, &points, "The quick brown fox jumps over the lazy dog")

	// Test verifiable secret sharing
	// XXX re-enable when we move this into 'test' sub-package
	//testSharing(g)

	// Test encoding and decoding
	buf := new(bytes.Buffer)
	for i := 0; i < 5; i++ {
		buf.Reset()
		s := suite.Scalar().Random(rand)
		if _, err := s.Marshal(suite.Context(), buf); err != nil {
			panic("encoding of secret fails: " + err.Error())
		}
		if _, err := stmp.Unmarshal(suite.Context(), buf); err != nil {
			panic("decoding of secret fails: " + err.Error())
		}
		if !stmp.Equal(s) {
			panic("decoding produces different secret than encoded")
		}

		buf.Reset()
		p := suite.Point().Random(rand)
		if _, err := p.Marshal(suite.Context(), buf); err != nil {
			panic("encoding of point fails: " + err.Error())
		}
		if _, err := ptmp.Unmarshal(suite.Context(), buf); err != nil {
			panic("decoding of point fails: " + err.Error())
		}
		if !ptmp.Equal(p) {
			panic("decoding produces different point than encoded")
		}
	}

	// Test that we can marshal/ unmarshal null point
	pzero = suite.Point().Null()
	b, _ := pzero.MarshalBinary()
	repzero := suite.Point()
	err := repzero.UnmarshalBinary(b)
	if err != nil {
		panic(err)
	}

	return points
}

// Apply a generic set of validation tests to a cryptographic Group.
func TestGroup(suite *abstract.Suite) {
	testGroup(suite, random.Fresh())
}

// Test two group implementations that are supposed to be equivalent,
// and compare their results.
func TestCompareGroups(s1, s2 *abstract.Suite) {

	// Produce test results from the same pseudorandom seed
	r1 := testGroup(s1, s1.Cipher(abstract.NoKey))
	r2 := testGroup(s2, s1.Cipher(abstract.NoKey))

	// Compare resulting Points
	for i := range r1 {
		b1, _ := r1[i].MarshalBinary()
		b2, _ := r2[i].MarshalBinary()
		if !bytes.Equal(b1, b2) {
			println("result-pair", i,
				"\n1:", r1[i].String(),
				"\n2:", r2[i].String())
			panic("unequal results")
		}
	}
}

// Apply a standard set of validation tests to a ciphersuite.
func TestSuite(suite *abstract.Suite) {

	// Try hashing something
	h := suite.Hash(abstract.NoKey)
	l := h.Size()
	//println("HashLen: ",l)
	h.Write([]byte("abc"))
	hb := h.Sum(nil)
	//println("Hash:")
	//println(hex.Dump(hb))
	if h.Size() != l || len(hb) != l {
		panic("inconsistent hash output length")
	}

	// Generate some pseudorandom bits
	s := suite.Cipher(hb)
	sb := make([]byte, 128)
	s.XORKeyStream(sb, sb)
	//println("Stream:")
	//println(hex.Dump(sb))

	// Test the public-key group arithmetic
	TestGroup(suite)
}
