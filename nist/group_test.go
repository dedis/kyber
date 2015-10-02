package nist

import (
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/test"
	"golang.org/x/net/context"
	"testing"
)

var ctxBase = sha3.WithShake128(context.Background())
var ctxQR512 = withQR512(ctxBase)

func TestQR512(t *testing.T) { test.TestSuite(ctxQR512) }

var ctxP256 = WithP256(ctxBase)
var benchP256 = test.NewGroupBench(ctxP256)

func TestP256(t *testing.T) { test.TestSuite(ctxP256) }

func BenchmarkScalarAdd(b *testing.B)    { benchP256.ScalarAdd(b.N) }
func BenchmarkScalarSub(b *testing.B)    { benchP256.ScalarSub(b.N) }
func BenchmarkScalarNeg(b *testing.B)    { benchP256.ScalarNeg(b.N) }
func BenchmarkScalarMul(b *testing.B)    { benchP256.ScalarMul(b.N) }
func BenchmarkScalarDiv(b *testing.B)    { benchP256.ScalarDiv(b.N) }
func BenchmarkScalarInv(b *testing.B)    { benchP256.ScalarInv(b.N) }
func BenchmarkScalarPick(b *testing.B)   { benchP256.ScalarPick(b.N) }
func BenchmarkScalarEncode(b *testing.B) { benchP256.ScalarEncode(b.N) }
func BenchmarkScalarDecode(b *testing.B) { benchP256.ScalarDecode(b.N) }

func BenchmarkPointAdd(b *testing.B)     { benchP256.PointAdd(b.N) }
func BenchmarkPointSub(b *testing.B)     { benchP256.PointSub(b.N) }
func BenchmarkPointNeg(b *testing.B)     { benchP256.PointNeg(b.N) }
func BenchmarkPointMul(b *testing.B)     { benchP256.PointMul(b.N) }
func BenchmarkPointBaseMul(b *testing.B) { benchP256.PointBaseMul(b.N) }
func BenchmarkPointPick(b *testing.B)    { benchP256.PointPick(b.N) }
func BenchmarkPointEncode(b *testing.B)  { benchP256.PointEncode(b.N) }
func BenchmarkPointDecode(b *testing.B)  { benchP256.PointDecode(b.N) }
