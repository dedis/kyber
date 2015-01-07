package ed25519

import (
	"github.com/dedis/crypto/test"
	"testing"
)

var testSuite = NewAES128SHA256Ed25519()

func TestGroup(t *testing.T) {
	test.TestSuite(testSuite)
}

func BenchmarkSecretAdd(b *testing.B) {
	test.NewGroupBench(testSuite).SecretAdd(b.N)
}

func BenchmarkSecretSub(b *testing.B) {
	test.NewGroupBench(testSuite).SecretSub(b.N)
}

func BenchmarkSecretNeg(b *testing.B) {
	test.NewGroupBench(testSuite).SecretNeg(b.N)
}

func BenchmarkSecretMul(b *testing.B) {
	test.NewGroupBench(testSuite).SecretMul(b.N)
}

func BenchmarkSecretDiv(b *testing.B) {
	test.NewGroupBench(testSuite).SecretDiv(b.N)
}

func BenchmarkSecretInv(b *testing.B) {
	test.NewGroupBench(testSuite).SecretInv(b.N)
}

func BenchmarkSecretPick(b *testing.B) {
	test.NewGroupBench(testSuite).SecretPick(b.N)
}

func BenchmarkSecretEncode(b *testing.B) {
	test.NewGroupBench(testSuite).SecretEncode(b.N)
}

func BenchmarkSecretDecode(b *testing.B) {
	test.NewGroupBench(testSuite).SecretDecode(b.N)
}

func BenchmarkPointAdd(b *testing.B) {
	test.NewGroupBench(testSuite).PointAdd(b.N)
}

func BenchmarkPointSub(b *testing.B) {
	test.NewGroupBench(testSuite).PointSub(b.N)
}

func BenchmarkPointNeg(b *testing.B) {
	test.NewGroupBench(testSuite).PointNeg(b.N)
}

func BenchmarkPointMul(b *testing.B) {
	test.NewGroupBench(testSuite).PointMul(b.N)
}

func BenchmarkPointBaseMul(b *testing.B) {
	test.NewGroupBench(testSuite).PointBaseMul(b.N)
}

func BenchmarkPointPick(b *testing.B) {
	test.NewGroupBench(testSuite).PointPick(b.N)
}

func BenchmarkPointEncode(b *testing.B) {
	test.NewGroupBench(testSuite).PointEncode(b.N)
}

func BenchmarkPointDecode(b *testing.B) {
	test.NewGroupBench(testSuite).PointDecode(b.N)
}
