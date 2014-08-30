package crypto

import (
	"bytes"
	"fmt"
	"time"
)


func testEmbed(g Group,s string) {
	//println("embedding: ",s)
	b := []byte(s)

	p,rem := g.Point().Pick(b, RandomStream)
	//println("embedded, remainder",len(rem),"/",len(b),":",string(rem))
	x,err := p.Data()
	if err != nil {
		panic("Point extraction failed: "+err.Error())
	}
	println("extracted data: ",string(x))

	if !bytes.Equal(append(x,rem...), b) {
		panic("Point embedding corrupted the data")
	}
}

// Apply a generic set of validation tests to a cryptographic Group.
func TestGroup(g Group) {
	fmt.Printf("\nTesting group '%s': %d-byte Point, %d-byte Secret\n",
			g.String(), g.PointLen(), g.SecretLen())

	// Do a simple Diffie-Hellman test
	s1 := g.Secret().Pick(RandomStream)
	s2 := g.Secret().Pick(RandomStream)
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	gen := g.Point().Base()
	p1 := g.Point().Mul(gen,s1)
	p2 := g.Point().Mul(gen,s2)
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}

	dh1 := g.Point().Mul(p1,s2)
	dh2 := g.Point().Mul(p2,s1)
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	println("shared secret = ",dh1.String())

	// Test secret inverse to get from dh1 back to p1
	ptmp := g.Point().Mul(dh1, g.Secret().Inv(s2))
	if !ptmp.Equal(p1) {
		panic("Secret inverse didn't work")
	}

	// Zero and One identity secrets
	//println("dh1^0 = ",ptmp.Mul(dh1, g.Secret().Zero()).String())
	if !ptmp.Mul(dh1, g.Secret().Zero()).Equal(g.Point().Null()) {
		panic("Encryption with secret=0 didn't work")
	}
	if !ptmp.Mul(dh1, g.Secret().One()).Equal(dh1) {
		panic("Encryption with secret=1 didn't work")
	}

	// Additive homomorphic identities
	ptmp.Add(p1,p2)
	stmp := g.Secret().Add(s1,s2)
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
	p1.Pick(nil, RandomStream)
	p2.Pick(nil, RandomStream)
	if p1.Equal(p2) {
		panic("Pick() not producing unique points")
	}

	// Test embedding data
	testEmbed(g,"Hi!")
	testEmbed(g,"The quick brown fox jumps over the lazy dog")

	// Test verifiable secret sharing
	testSharing(g)
}

// A simple microbenchmark suite for abstract group functionality.
func BenchGroup(g Group) {

	// Point addition
	b := g.Point().Base()
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

