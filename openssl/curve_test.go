package openssl

import (
	"github.com/dedis/crypto/test"
	"github.com/dedis/crypto/cipher/sha3"
	"testing"
	"golang.org/x/net/context"
)

var ctxBase = sha3.WithShake128(context.Background())
var ctxP224 = WithP224(ctxBase)
var ctxP256 = WithP256(ctxBase)
var ctxP384 = WithP384(ctxBase)
var ctxP521 = WithP521(ctxBase)

var groupBench = test.NewGroupBench(ctxP256)

func TestP224(t *testing.T) { test.TestGroup(ctxP224) }
func TestP256(t *testing.T) { test.TestGroup(ctxP256) }
func TestP384(t *testing.T) { test.TestGroup(ctxP384) }
func TestP521(t *testing.T) { test.TestGroup(ctxP521) }

func TestSuite(t *testing.T) { test.TestSuite(ctxP256) }

func BenchmarkScalarAdd(b *testing.B)    { groupBench.ScalarAdd(b.N) }
func BenchmarkScalarSub(b *testing.B)    { groupBench.ScalarSub(b.N) }
func BenchmarkScalarNeg(b *testing.B)    { groupBench.ScalarNeg(b.N) }
func BenchmarkScalarMul(b *testing.B)    { groupBench.ScalarMul(b.N) }
func BenchmarkScalarDiv(b *testing.B)    { groupBench.ScalarDiv(b.N) }
func BenchmarkScalarInv(b *testing.B)    { groupBench.ScalarInv(b.N) }
func BenchmarkScalarPick(b *testing.B)   { groupBench.ScalarPick(b.N) }
func BenchmarkScalarEncode(b *testing.B) { groupBench.ScalarEncode(b.N) }
func BenchmarkScalarDecode(b *testing.B) { groupBench.ScalarDecode(b.N) }

func BenchmarkPointAdd(b *testing.B)     { groupBench.PointAdd(b.N) }
func BenchmarkPointSub(b *testing.B)     { groupBench.PointSub(b.N) }
func BenchmarkPointNeg(b *testing.B)     { groupBench.PointNeg(b.N) }
func BenchmarkPointMul(b *testing.B)     { groupBench.PointMul(b.N) }
func BenchmarkPointBaseMul(b *testing.B) { groupBench.PointBaseMul(b.N) }
func BenchmarkPointPick(b *testing.B)    { groupBench.PointPick(b.N) }
func BenchmarkPointEncode(b *testing.B)  { groupBench.PointEncode(b.N) }
func BenchmarkPointDecode(b *testing.B)  { groupBench.PointDecode(b.N) }
