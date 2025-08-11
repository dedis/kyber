//go:build !constantTime

package edwards25519

// todo understand this test
// Test_ScalarIsCanonical ensures that scalars >= primeOrder are
// considered non canonical.
//func Test_ScalarIsCanonical(t *testing.T) {
//	candidate := compatible.NewInt(-2)
//	candidate.Add(candidate.Int, primeOrder.Int, )
//
//	candidateBuf := candidate.Bytes()
//	for i, j := 0, len(candidateBuf)-1; i < j; i, j = i+1, j-1 {
//		candidateBuf[i], candidateBuf[j] = candidateBuf[j], candidateBuf[i]
//	}
//
//	expected := []bool{true, true, false, false}
//	scalar := scalar{}
//
//	// We check in range [L-2, L+4)
//	for i := 0; i < 4; i++ {
//		require.Equal(t, expected[i], scalar.IsCanonical(candidateBuf), fmt.Sprintf("`lMinus2 + %d` does not pass canonicality test", i))
//		candidateBuf[0]++
//	}
//}
