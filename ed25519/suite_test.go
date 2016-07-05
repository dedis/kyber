package ed25519

import (
	"testing"

	//"fmt"

	"github.com/stretchr/testify/assert"
)

var edSuite = NewAES128SHA256Ed25519(false)

func TestCurvePointClone(t *testing.T) {
	P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
	P2 := P1.Clone()
	assert.True(t, P1.Equal(P2))
}

func TestCurvePointCloneRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Randomized test skipped in short mode")
	}
	iters := 1000
	null := edSuite.Point().Null()
	for iters > 0 {
		P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
		P2 := P1.Clone()
		assert.True(t, P1.Equal(P2))
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			assert.False(t, P1.Equal(P2))
		}

		iters--
	}
}

func TestCurvePointSet(t *testing.T) {
	P1, _ := edSuite.Point().Pick([]byte("one_point"), edSuite.Cipher(nil))
	P2 := edSuite.Point()
	P2.Set(P1)
	assert.True(t, P1.Equal(P2))

	P1.Add(P1, P1)
	assert.False(t, P1.Equal(P2))
}

func TestCurvePointRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Randomized test skipped in short mode")
	}
	iters := 1000
	null := edSuite.Point().Null()
	for iters > 0 {

		P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
		P2 := edSuite.Point()
		P2.Set(P1)
		assert.True(t, P1.Equal(P2))
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			assert.False(t, P1.Equal(P2))
		}
		iters--
	}
}

/*
func (P *point) CloneInternal() abstract.Point {
	p2 := &point{}
	p2.ge = P.ge
	return p2
}

func (P *point) CloneMarshal() abstract.Point {
	p2 := suite.Point()
	b,_:= P.MarshalBinary()
	p2.UnmarshalBinary(b)
	return p2
}

func (P *point) CloneAdd() abstract.Point {
	p2 := suite.Point().Null()

	p2.Add(p2, abstract.Point(P))
	return p2
}

func (P *point) CloneMul() abstract.Point {
	p2 := suite.Point()
	p2.Mul(P, suite.Scalar().One())

	return p2
}


func BenchmarkCloneInternal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		P1,_ := suite.Point().Pick(nil, suite.Cipher(nil))
		b.StartTimer()
		P2 := P1.(*point).CloneInternal()

		if !P1.Equal(P2) {
			b.Fatal("Not equal")
		}

	}
}

func BenchmarkCloneMarshal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		P1,_ := suite.Point().Pick(nil, suite.Cipher(nil))
		b.StartTimer()
		P2 := P1.(*point).CloneMarshal()

		if !P1.Equal(P2) {
			b.Fatal("Not equal")
		}
	}
}

func BenchmarkCloneAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		P1,_ := suite.Point().Pick(nil, suite.Cipher(nil))
		b.StartTimer()
		P2 := P1.(*point).CloneAdd()

		if !P1.Equal(P2) {
			b.Fatal("Not equal")
		}
	}
}

func BenchmarkCloneMul(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		P1,_ := suite.Point().Pick(nil, suite.Cipher(nil))
		b.StartTimer()
		P2 := P1.(*point).CloneMul()

		if !P1.Equal(P2) {
			b.Fatal("Not equal")
		}
	}
}
*/