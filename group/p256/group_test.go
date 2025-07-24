//go:build !constantTime

package p256

import (
	"encoding/hex"
	"go.dedis.ch/kyber/v4/compatible"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/util/test"
)

var testQR512 = NewBlakeSHA256QR512()

func TestQR512(t *testing.T) { test.SuiteTest(t, testQR512) }

var testP256 = NewBlakeSHA256P256()

func TestP256(t *testing.T) { test.SuiteTest(t, testP256) }

func TestSetBytesBE(t *testing.T) {
	s := testP256.Scalar()
	s.SetBytes([]byte{0, 1, 2, 3})
	// 010203 because initial 0 is trimmed in String(), and 03 (last byte of BE) ends up
	// in the LSB of the bigint.
	if s.String() != "010203" {
		t.Fatal("unexpected result from String():", s.String())
	}
}

func TestVectors(t *testing.T) {
	k := compatible.NewInt(0)
	s := testP256.Scalar()

	BasePoint := testP256.Point().Base().(*curvePoint)
	BasePoint.x.SetString(basePointScalarMult[0].X, 16)
	BasePoint.y.SetString(basePointScalarMult[0].Y, 16)

	for _, vec := range basePointScalarMult {
		// Read from strings
		k, ok := k.SetString(vec.K, 10)
		require.Equal(t, true, ok)
		s.SetBytes(k.Bytes())

		Q := testP256.Point().Mul(s, BasePoint).(*curvePoint)
		require.Equal(t, strings.ToLower(vec.X), hex.EncodeToString(Q.x.Bytes()))
		require.Equal(t, strings.ToLower(vec.Y), hex.EncodeToString(Q.y.Bytes()))
	}
}

var benchP256 = test.NewGroupBench(testP256)

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
