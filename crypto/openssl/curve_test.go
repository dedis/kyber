package openssl

import (
	"testing"
	"dissent/crypto"
	"dissent/crypto/bench"
)

var testSuite = NewAES128SHA256P256()


func TestP224(t *testing.T) {
	crypto.TestGroup(new(curve).InitP224())
}

func TestP256(t *testing.T) {
	crypto.TestGroup(new(curve).InitP256())
}

func TestP384(t *testing.T) {
	crypto.TestGroup(new(curve).InitP384())
}

func TestP521(t *testing.T) {
	crypto.TestGroup(new(curve).InitP521())
}


func TestSuite(t *testing.T) {
	crypto.TestSuite(testSuite)
}


func BenchmarkSecretAdd(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretAdd()
}

func BenchmarkSecretSub(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretSub()
}

func BenchmarkSecretNeg(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretNeg()
}

func BenchmarkSecretMul(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretMul()
}

func BenchmarkSecretDiv(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretDiv()
}

func BenchmarkSecretInv(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretInv()
}

func BenchmarkSecretPick(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretPick()
}

func BenchmarkSecretEncode(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretEncode()
}

func BenchmarkSecretDecode(b *testing.B) {
	bench.NewSecretBench(b,testSuite).SecretDecode()
}


func BenchmarkPointAdd(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointAdd()
}

func BenchmarkPointSub(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointSub()
}

func BenchmarkPointNeg(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointNeg()
}

func BenchmarkPointMul(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointMul()
}

func BenchmarkPointBaseMul(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointBaseMul()
}

func BenchmarkPointPick(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointPick()
}

func BenchmarkPointEncode(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointEncode()
}

func BenchmarkPointDecode(b *testing.B) {
	bench.NewPointBench(b,testSuite).PointDecode()
}

