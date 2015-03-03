package nist

import (
	"github.com/dedis/crypto/test"
	"testing"
)

var testQR512 = NewAES128SHA256QR512()

func TestQR512(t *testing.T) { test.TestSuite(testQR512) }

var testP256 = NewAES128SHA256P256()
var benchP256 = test.NewGroupBench(testP256)

func TestP256(t *testing.T) { test.TestSuite(testP256) }

func BenchmarkSecretAdd(b *testing.B)    { benchP256.SecretAdd(b.N) }
func BenchmarkSecretSub(b *testing.B)    { benchP256.SecretSub(b.N) }
func BenchmarkSecretNeg(b *testing.B)    { benchP256.SecretNeg(b.N) }
func BenchmarkSecretMul(b *testing.B)    { benchP256.SecretMul(b.N) }
func BenchmarkSecretDiv(b *testing.B)    { benchP256.SecretDiv(b.N) }
func BenchmarkSecretInv(b *testing.B)    { benchP256.SecretInv(b.N) }
func BenchmarkSecretPick(b *testing.B)   { benchP256.SecretPick(b.N) }
func BenchmarkSecretEncode(b *testing.B) { benchP256.SecretEncode(b.N) }
func BenchmarkSecretDecode(b *testing.B) { benchP256.SecretDecode(b.N) }

func BenchmarkPointAdd(b *testing.B)     { benchP256.PointAdd(b.N) }
func BenchmarkPointSub(b *testing.B)     { benchP256.PointSub(b.N) }
func BenchmarkPointNeg(b *testing.B)     { benchP256.PointNeg(b.N) }
func BenchmarkPointMul(b *testing.B)     { benchP256.PointMul(b.N) }
func BenchmarkPointBaseMul(b *testing.B) { benchP256.PointBaseMul(b.N) }
func BenchmarkPointPick(b *testing.B)    { benchP256.PointPick(b.N) }
func BenchmarkPointEncode(b *testing.B)  { benchP256.PointEncode(b.N) }
func BenchmarkPointDecode(b *testing.B)  { benchP256.PointDecode(b.N) }
