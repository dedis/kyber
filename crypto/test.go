package crypto

import (
	"fmt"
	"time"
	"hash"
	"bytes"
	"testing"
	"crypto/cipher"
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
	//println("extracted data: ",string(x))

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
	//println("shared secret = ",dh1.String())

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

// A generic benchmark suite for abstract groups.
type GroupBench struct {
	b *testing.B
	g Group

	// Random secrets and points for testing
	x,y Secret
	X,Y Point
	xe []byte	// encoded Secret
	Xe []byte	// encoded Point
}

func newGroupBench(b *testing.B, g Group, len int) *GroupBench {
	var gb GroupBench
	gb.b = b
	gb.g = g
	gb.x = g.Secret().Pick(RandomStream)
	gb.y = g.Secret().Pick(RandomStream)
	gb.xe = gb.x.Encode()
	gb.X,_ = g.Point().Pick(nil, RandomStream)
	gb.Y,_ = g.Point().Pick(nil, RandomStream)
	gb.Xe = gb.X.Encode()
	b.SetBytes(int64(len))
	return &gb
}

func NewSecretBench(b *testing.B, g Group) *GroupBench {
	return newGroupBench(b, g, g.SecretLen())
}

func (gb GroupBench) SecretAdd() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Add(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretSub() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Sub(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretNeg() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Neg(gb.x)
	}
}

func (gb GroupBench) SecretMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Mul(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretDiv() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Div(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretInv() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Inv(gb.x)
	}
}

func (gb GroupBench) SecretPick() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Pick(RandomStream)
	}
}

func (gb GroupBench) SecretEncode() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Encode()
	}
}

func (gb GroupBench) SecretDecode() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Decode(gb.xe)
	}
}


func NewPointBench(b *testing.B, g Group) *GroupBench {
	return newGroupBench(b, g, g.PointLen())
}

func (gb GroupBench) PointAdd() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Add(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointSub() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Sub(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointNeg() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Neg(gb.X)
	}
}

func (gb GroupBench) PointMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Mul(gb.X,gb.y)
	}
}

func (gb GroupBench) PointBaseMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Mul(nil,gb.y)
	}
}

func (gb GroupBench) PointPick() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Pick(nil, RandomStream)
	}
}

func (gb GroupBench) PointEncode() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Encode()
	}
}

func (gb GroupBench) PointDecode() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Decode(gb.Xe)
	}
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



func HashBench(b *testing.B, hash func() hash.Hash) {
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		h := hash()
		for j := 0; j < 1024; j++ {
			h.Write(data)
		}
		h.Sum(nil)
	}
}

// Benchmark a stream cipher.
func StreamCipherBench(b *testing.B, keylen int,
			cipher func([]byte) cipher.Stream) {
	key := make([]byte, keylen)
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		c := cipher(key)
		for j := 0; j < 1024; j++ {
			c.XORKeyStream(data,data)
		}
	}
}

// Benchmark a block cipher operating in counter mode.
func BlockCipherBench(b *testing.B, keylen int,
			bcipher func([]byte) cipher.Block) {
	StreamCipherBench(b, keylen, func(key []byte) cipher.Stream {
		bc := bcipher(key)
		iv := make([]byte,bc.BlockSize())
		return cipher.NewCTR(bc,iv)
	})
}

