package crypto

import (
	"fmt"
	"time"
	"bytes"
	"crypto/cipher"
)


func testEmbed(g Group, rand cipher.Stream, points *[]Point, s string) {
	//println("embedding: ",s)
	b := []byte(s)

	p,rem := g.Point().Pick(b, rand)
	//println("embedded, remainder",len(rem),"/",len(b),":",string(rem))
	x,err := p.Data()
	if err != nil {
		panic("Point extraction failed: "+err.Error())
	}
	//println("extracted data: ",string(x))

	if !bytes.Equal(append(x,rem...), b) {
		panic("Point embedding corrupted the data")
	}

	*points = append(*points,p)
}

// Apply a generic set of validation tests to a cryptographic Group,
// using a given source of [pseudo-]randomness.
//
// Returns a log of the pseudorandom Points produced in the test,
// for comparison across alternative implementations
// that are supposed to be equivalent.
//
func testGroup(g Group, rand cipher.Stream) []Point {
	fmt.Printf("\nTesting group '%s': %d-byte Point, %d-byte Secret\n",
			g.String(), g.PointLen(), g.SecretLen())

	points := make([]Point,0)
	ptmp := g.Point()
	stmp := g.Secret()
	pzero := g.Point().Null()
	szero := g.Secret().Zero()
	sone := g.Secret().One()

	// Do a simple Diffie-Hellman test
	s1 := g.Secret().Pick(rand)
	s2 := g.Secret().Pick(rand)
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	gen := g.Point().Base(nil)
	points = append(points,gen)

	// Verify additive and multiplicative identities of the generator.
	ptmp.Mul(nil,stmp.SetInt64(-1)).Add(ptmp,gen)
	if !ptmp.Equal(pzero) {
		panic("oops, generator additive identity doesn't work")
	}
	ptmp.Mul(nil,stmp.SetInt64(2)).Mul(ptmp,stmp.Inv(stmp))
	if !ptmp.Equal(gen) {
		panic("oops, generator multiplicative identity doesn't work")
	}

	p1 := g.Point().Mul(gen,s1)
	p2 := g.Point().Mul(gen,s2)
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}
	points = append(points,p1)

	dh1 := g.Point().Mul(p1,s2)
	dh2 := g.Point().Mul(p2,s1)
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	points = append(points,dh1)
	//println("shared secret = ",dh1.String())

	// Test secret inverse to get from dh1 back to p1
	ptmp.Mul(dh1, g.Secret().Inv(s2))
	if !ptmp.Equal(p1) {
		panic("Secret inverse didn't work")
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
	ptmp.Add(p1,p2)
	stmp.Add(s1,s2)
	pt2 := g.Point().Mul(gen,stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	ptmp.Sub(p1,p2)
	stmp.Sub(s1,s2)
	pt2.Mul(gen,stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	st2 := g.Secret().Neg(s2)
	st2.Add(s1,st2)
	if !stmp.Equal(st2) {
		panic("Secret.Neg doesn't work")
	}
	pt2.Neg(p2).Add(pt2,p1)
	if !pt2.Equal(ptmp) {
		panic("Point.Neg doesn't work")
	}

	// Multiplicative homomorphic identities
	stmp.Mul(s1,s2)
	if !ptmp.Mul(gen,stmp).Equal(dh1) {
		panic("Multiplicative homomorphism doesn't work")
	}
	st2.Inv(s2)
	st2.Mul(st2,stmp)
	if !st2.Equal(s1) {
		panic("Secret division doesn't work")
	}
	st2.Div(stmp,s2)
	if !st2.Equal(s1) {
		panic("Secret division doesn't work")
	}

	// Test randomly picked points
	pick1,_ := g.Point().Pick(nil, rand)
	pick2,_ := g.Point().Pick(nil, rand)
	if p1.Equal(p2) {
		panic("Pick() not producing unique points")
	}
	points = append(points,pick1)
	points = append(points,pick2)

	// Test pseudorandom generators
	for i := 0; i < 5; i++ {
		rgen := g.Point().Base(rand)
		ptmp.Mul(rgen,stmp.SetInt64(-1)).Add(ptmp,rgen)
		if !ptmp.Equal(pzero) {
			panic("random generator fails additive identity")
		}
		ptmp.Mul(rgen,stmp.SetInt64(2)).Mul(ptmp,stmp.Inv(stmp))
		if !ptmp.Equal(rgen) {
			panic("random generator fails multiplicative identity")
		}
		points = append(points,rgen)
	}

	// Test embedding data
	testEmbed(g,rand,&points,"Hi!")
	testEmbed(g,rand,&points,"The quick brown fox jumps over the lazy dog")

	// Test verifiable secret sharing
	testSharing(g)

	return points
}

// Apply a generic set of validation tests to a cryptographic Group.
func TestGroup(g Group) {
	testGroup(g, RandomStream)
}

// Test two group implementations that are supposed to be equivalent,
// and compare their results.
func TestCompareGroups(g1,g2 Group) {

	// Use any ciphersuite to produce psuedorandom bits
	suite := NewAES128SHA256P256()
	//seed := make([]byte, 0)

	// Produce test results from the same pseudorandom seed
	r1 := testGroup(g1, HashStream(suite, nil, nil))
	r2 := testGroup(g2, HashStream(suite, nil, nil))

	// Compare resulting Points
	for i := range(r1) {
		b1 := r1[i].Encode()
		b2 := r2[i].Encode()
		if !bytes.Equal(b1,b2) {
			println("result-pair",i,
				"\n1:",r1[i].String(),
				"\n2:",r2[i].String())
			panic("unequal results")
		}
	}
}

// A simple microbenchmark suite for abstract group functionality.
func BenchGroup(g Group) {

	// Point addition
	b := g.Point().Base(nil)
	p := g.Point()
	p.Pick(nil, RandomStream)
	beg := time.Now()
	iters := 10000
	for i := 1; i < iters; i++ {
		p.Add(p,b)
	}
	end := time.Now()
	fmt.Printf("Point.Add: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Point encryption
	s := g.Secret().Pick(RandomStream)
	beg = time.Now()
	iters = 500
	for i := 1; i < iters; i++ {
		p.Mul(p,s)
	}
	end = time.Now()
	fmt.Printf("Point.Mul: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Data embedding
	beg = time.Now()
	iters = 2000
	for i := 1; i < iters; i++ {
		p.Pick([]byte("abc"), RandomStream)
	}
	end = time.Now()
	fmt.Printf("Point.Pick: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret addition (in-place arithmetic)
	s2 := g.Secret().Pick(RandomStream)
	beg = time.Now()
	iters = 10000000
	for i := 1; i < iters; i++ {
		s.Add(s,s2)
	}
	end = time.Now()
	fmt.Printf("Secret.Add: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret multiplication
	beg = time.Now()
	iters = 1000000
	for i := 1; i < iters; i++ {
		s.Mul(s,s2)
	}
	end = time.Now()
	fmt.Printf("Secret.Mul: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret inversion
	beg = time.Now()
	iters = 10000
	for i := 1; i < iters; i++ {
		s.Inv(s)
	}
	end = time.Now()
	fmt.Printf("Secret.Inv: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	println()
}

