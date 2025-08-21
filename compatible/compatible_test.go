//go:build constantTime

package compatible

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"math/big"
	"testing"
)

func TestBigIntToNatConversion(t *testing.T) {
	// Create a test big integer
	bigValue, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250987", 10)
	bigMod, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	// Convert to nat
	natMod := compatible_mod.FromBigInt(bigMod)
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
	natMod := compatible_mod.FromBigInt(bigMod)
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
	natMod := compatible_mod.FromBigInt(bigMod)
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
	natMod, _ := compatible_mod.FromString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
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
	natMod, _ := compatible_mod.FromString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
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
		natMod := compatible_mod.FromBigInt(bigMod)
		natValue := FromBigInt(bigValue, natMod)
		natInverse := NewInt(0).ModInverse(natValue, natMod)
		hasNatInverse := natInverse != nil

		fmt.Println(bigMod, natMod, bigValue, natValue, bigInverse, natInverse, hasBigInverse, hasNatInverse, tc.hasInverse)
		if hasBigInverse != tc.hasInverse {
			t.Errorf("big.Int ModInverse existence mismatch for %v mod %v: got %v, want %v",
				tc.value, tc.modulus, hasBigInverse, tc.hasInverse)
		}

		if hasNatInverse != tc.hasInverse {
			t.Errorf("Compatible ModInverse existence mismatch for %v mod %v: got %v, want %v",
				tc.value, tc.modulus, hasNatInverse, tc.hasInverse)
		}

		if tc.hasInverse {
			if bigInverse.Cmp(natInverse.ToBigInt()) != 0 {
				t.Errorf("ModInverse result mismatch for %v mod %v: got %v, want %v",
					tc.value, tc.modulus, natInverse.ToBigInt(), bigInverse)
			}
		}
	}
}

func TestSet(t *testing.T) {
	a := NewInt(1)
	z := NewInt(0)
	fmt.Println("Before Set - z:", z, "a:", a)
	z.Set(a)
	fmt.Println("After Set - z:", z, "a:", a)
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
	mod := compatible_mod.NewInt(171)
	initial := NewInt(330)
	a := NewInt(0).Mod(initial, mod)
	fmt.Println(a)
}

func TestSimpleMultiplication(t *testing.T) {
	m := compatible_mod.NewInt(171)
	a := NewInt(0).Mul(NewInt(33), NewInt(100), m)
	fmt.Println(a)
}
