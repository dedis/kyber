package openssl

import (
	"testing"
	"dissent/crypto"
)

var testSuite = NewAES128SHA256P256()


func TestGroup(t *testing.T) {
	crypto.TestSuite(testSuite)
}


func BenchmarkSecretAdd(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretAdd()
}

func BenchmarkSecretSub(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretSub()
}

func BenchmarkSecretNeg(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretNeg()
}

func BenchmarkSecretMul(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretMul()
}

func BenchmarkSecretDiv(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretDiv()
}

func BenchmarkSecretInv(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretInv()
}

func BenchmarkSecretPick(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretPick()
}

func BenchmarkSecretEncode(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretEncode()
}

func BenchmarkSecretDecode(b *testing.B) {
	crypto.NewSecretBench(b,testSuite).SecretDecode()
}


func BenchmarkPointAdd(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointAdd()
}

func BenchmarkPointSub(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointSub()
}

func BenchmarkPointNeg(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointNeg()
}

func BenchmarkPointMul(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointMul()
}

func BenchmarkPointBaseMul(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointBaseMul()
}

func BenchmarkPointPick(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointPick()
}

func BenchmarkPointEncode(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointEncode()
}

func BenchmarkPointDecode(b *testing.B) {
	crypto.NewPointBench(b,testSuite).PointDecode()
}

