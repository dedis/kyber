//go:build constantTime

package compatible

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/compatible/bigmod"
	"go.dedis.ch/kyber/v4/compatible/compatiblemod"
)

func TestBigIntToNatConversion(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod := compatiblemod.FromBigInt(bigMod)
	natValue := FromBigInt(bigValue, natMod)

	// Convert back to big.Int
	resultValue := natValue.ToBigInt()
	resultMod := natMod.ToBigInt()
	// Check if the result matches the original
	if bigValue.Cmp(resultValue) != 0 {
		t.Errorf("Value conversion mismatch: got %v, want %v", resultValue, bigValue)
	}
	if bigMod.Cmp(resultMod) != 0 {
		t.Errorf("Mod conversion mismatch: got %v, want %v", resultMod, bigMod)
	}

}

func TestBit(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod := compatiblemod.FromBigInt(bigMod)
	natValue := FromBigInt(bigValue, natMod)

	// Convert back to big.Int
	for i := 0; i < 255; i++ {
		resultValue := natValue.Bit(i)
		bigValueBit := bigValue.Bit(i)
		resultMod := natMod.Bit(i)
		bigModBit := bigMod.Bit(i)
		// Check if the result matches the original
		if bigValueBit != resultValue {
			t.Errorf("Value conversion mismatch: got %v, want %v", resultValue, bigValue)
		}
		if bigModBit != resultMod {
			t.Errorf("Mod conversion mismatch: got %v, want %v", resultMod, bigMod)
		}
		//fmt.Println(bigModBit, resultMod, bigValueBit, resultValue, i)
	}
}

func TestFillBytes(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod := compatiblemod.FromBigInt(bigMod)
	natValue := FromBigInt(bigValue, natMod)

	// Create byte slices of equal length for both implementations
	bigBytes := make([]byte, (bigValue.BitLen()+7)/8)
	natBytes := make([]byte, (natValue.BitLen()+7)/8)

	// Fill bytes using both implementations
	bigValue.FillBytes(bigBytes)
	natValue.FillBytes(natBytes)

	// Compare results
	if string(bigBytes) != string(natBytes) {
		t.Errorf("FillBytes mismatch: got %v, want %v", natBytes, bigBytes)
	}
	//fmt.Println(string(bigBytes))
}

func TestStringConversion(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod, _ := compatiblemod.FromString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	natValue, _ := new(Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", "115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert back to big.Int
	resultValue := natValue.ToBigInt()
	resultMod := natMod.ToBigInt()
	// Check if the result matches the original
	if bigValue.Cmp(resultValue) != 0 {
		t.Errorf("Value conversion mismatch: got %v, want %v", resultValue, bigValue)
	}
	if bigMod.Cmp(resultMod) != 0 {
		t.Errorf("Mod conversion mismatch: got %v, want %v", resultMod, bigMod)
	}
}

func TestStringMConversion(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod, _ := compatiblemod.FromString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	natValue, _ := new(Int).SetStringM("7237005577332262213973186563042994240857116359379907606001950938285454250987", natMod, 10)

	// Convert back to big.Int
	resultValue := natValue.ToBigInt()
	resultMod := natMod.ToBigInt()
	// Check if the result matches the original
	if bigValue.Cmp(resultValue) != 0 {
		t.Errorf("Value conversion mismatch: got %v, want %v", resultValue, bigValue)
	}
	if bigMod.Cmp(resultMod) != 0 {
		t.Errorf("Mod conversion mismatch: got %v, want %v", resultMod, bigMod)
	}
}

func TestModInverse(t *testing.T) {
	testCases := []struct {
		value      string
		modulus    string
		hasInverse bool
	}{
		{"7", "13", true},
		{"3", "7", true},
	}

	for _, tc := range testCases {
		bigValue, _ := new(big.Int).SetString(tc.value, 10)
		bigMod, _ := new(big.Int).SetString(tc.modulus, 10)

		// big.Int implementation
		bigResult := new(big.Int)
		bigInverse := bigResult.ModInverse(bigValue, bigMod)
		hasBigInverse := bigInverse != nil

		// Compatible implementation
		natMod := compatiblemod.FromBigInt(bigMod)
		natValue := FromBigInt(bigValue, natMod)
		natInverse := NewInt(0).ModInverse(natValue, natMod)
		hasNatInverse := natInverse != nil

		require.Equal(t, tc.hasInverse, hasBigInverse,
			"big.Int ModInverse existence mismatch for %v mod %v: got %v, want %v",
			tc.value, tc.modulus, hasBigInverse, tc.hasInverse)

		require.Equal(t, hasNatInverse, tc.hasInverse,
			"Compatible ModInverse existence mismatch for %v mod %v: got %v, want %v",
			tc.value, tc.modulus, hasNatInverse, tc.hasInverse)

		if tc.hasInverse {
			require.NotNil(t, natInverse)
			require.NotNil(t, bigInverse)
			cmp := bigInverse.Cmp(natInverse.ToBigInt()) == 0
			require.True(t, cmp, "ModInverse result mismatch for %v mod %v: got %v, want %v",
				tc.value, tc.modulus, natInverse.ToBigInt(), bigInverse)
		}
	}
}

func TestSet(t *testing.T) {
	a := NewInt(1)
	z := NewInt(0)
	//fmt.Println("Before Set - z:", z, "a:", a)
	z.Set(a)
	//fmt.Println("After Set - z:", z, "a:", a)
	assert.Equal(t, z, a)
}

func TestMultiplication(t *testing.T) {
	a := NewInt(17)
	b := NewInt(19)
	c := NewInt(23)
	res := NewInt(29).Mul(a, b, c.ToCompatibleMod())
	aBig := a.ToBigInt()
	bBig := b.ToBigInt()
	cBig := c.ToBigInt()
	resBig := new(big.Int)
	resBig.Mul(aBig, bBig)
	resBig.Mod(resBig, cBig)
	if resBig.Cmp(res.ToBigInt()) != 0 {
		t.Errorf("Multiplication result mismatch: got %v, want %v", resBig, res.ToBigInt())
	}
	assert.Equal(t, resBig, res.ToBigInt())
	assert.Equal(t, res.String(), "1")
}

func TestSimpleMod(t *testing.T) {
	mod := compatiblemod.NewInt(171)
	initial := NewInt(330)
	a := NewInt(0).Mod(initial, mod)
	assert.Equal(t, a.String(), "159")
}

// TestModBigValue tries to reduce some value y
// to a modulo m that is much smaller
func TestModBigValue(t *testing.T) {
	m := compatiblemod.NewInt(10)
	yString := "827558546416454053910646459967499077875692070827048470514597884" +
		"3068036293136545469041005834638038226287677059608122477063777890173496873433711927663608414"
	yMod, ok := new(compatiblemod.Mod).SetString(yString, 10)
	require.True(t, ok)
	y := FromNat(yMod.Nat())

	res := y.Mod(y, m)
	require.Equal(t, bigmod.Yes, m.Modulus.Nat().CmpGeq(&res.Int))

	// Compare to math/big to validate
	mBigInt := big.NewInt(10)
	yBigInt, ok := new(big.Int).SetString(yString, 10)
	require.True(t, ok)
	expected := yBigInt.Mod(yBigInt, mBigInt)
	require.Equal(t, 0, expected.Cmp(res.ToBigInt()))
}

func TestSimpleMultiplication(t *testing.T) {
	m := compatiblemod.NewInt(171)
	a := NewInt(0).Mul(NewInt(33), NewInt(100), m)
	assert.Equal(t, a.String(), "51")
}

// TestSetBytesMod tries to call SetBytesMod() and expect that
// the value returned is correctly modded and no errors occurred
func TestSetBytesMod(t *testing.T) {
	m := compatiblemod.NewInt(10)
	yString := "827558546416454053910646459967499077875692070827048470514597884"
	// Use math/big to get the bytes and also validate the result
	yBigInt, ok := new(big.Int).SetString(yString, 10)
	require.True(t, ok)
	mBigInt := big.NewInt(10)

	y := new(Int).SetBytesMod(yBigInt.Bytes(), m)

	// Validate the result using math/big
	expected := yBigInt.Mod(yBigInt, mBigInt)
	require.Equal(t, 0, expected.Cmp(y.ToBigInt()))
}
