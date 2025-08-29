package mod

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"go.dedis.ch/kyber/v4/compatible"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v4"
)

func TestIntEndianness(t *testing.T) {
	modulo := compatible_mod.NewInt(65535)
	var v int64 = 65500
	// Let's assume it is bigendian and test that
	i := new(Int).Init64(v, modulo)
	assert.Equal(t, i.BO, kyber.BigEndian)

	buff1, err := i.MarshalBinary()
	assert.Nil(t, err)
	i.BO = kyber.BigEndian
	buff2, err := i.MarshalBinary()
	assert.Nil(t, err)
	assert.Equal(t, buff1, buff2)

	// Let's change endianness and check the result
	i.BO = kyber.LittleEndian
	buff3, err := i.MarshalBinary()
	assert.Nil(t, err)
	assert.NotEqual(t, buff2, buff3)

	// let's try LittleEndian function
	buff4 := i.LittleEndian(0, 32)
	assert.Equal(t, buff3, buff4)
	// set endianess but using littleendian should not change anything
	i.BO = kyber.BigEndian
	assert.Equal(t, buff4, i.LittleEndian(0, 32))

	// Try to reconstruct the int from the buffer
	i = new(Int).Init64(v, modulo)
	i2 := NewInt64(0, modulo)
	buff, _ := i.MarshalBinary()
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.True(t, i.Equal(i2))

	i.BO = kyber.LittleEndian
	buff, _ = i.MarshalBinary()
	i2.BO = kyber.LittleEndian
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.True(t, i.Equal(i2))

	i2.BO = kyber.BigEndian
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.False(t, i.Equal(i2))
}
func TestIntEndianBytes(t *testing.T) {
	modulo, err := hex.DecodeString("1000")
	assert.Nil(t, err)
	moduloI := new(compatible_mod.Mod).SetBytes(modulo)
	v, err := hex.DecodeString("10")
	assert.Nil(t, err)

	i := new(Int).InitBytes(v, moduloI, kyber.BigEndian)

	assert.Equal(t, 2, i.MarshalSize())
	assert.NotPanics(t, func() { i.LittleEndian(2, 2) })
}

func TestInits(t *testing.T) {
	i1 := NewInt64(int64(65500), compatible_mod.NewInt(65535))
	i2 := NewInt(&i1.V, i1.M)
	assert.True(t, i1.Equal(i2))
	b, _ := i1.MarshalBinary()
	i3 := NewIntBytes(b, i1.M, kyber.BigEndian)
	assert.True(t, i1.Equal(i3))
	i4 := NewIntString(i1.String(), "", 16, i1.M)
	assert.True(t, i1.Equal(i4))
}

func TestIntClone(t *testing.T) {
	moduloI := new(compatible_mod.Mod).SetBytes([]byte{0x10, 0})
	base := new(Int).InitBytes([]byte{0x10}, moduloI, kyber.BigEndian)

	clone := base.Clone()
	clone.Add(clone, clone)
	b1, _ := clone.MarshalBinary()
	b2, _ := base.MarshalBinary()
	if bytes.Equal(b1, b2) {
		t.Error("Should not be equal")
	}
}

func TestSetString7mod17(t *testing.T) {
	mod := compatible_mod.NewInt(17)
	initial := compatible.NewInt(3)
	i := NewInt(initial, mod)
	i.SetString("7", "", 16)
	assert.Equal(t, "07", i.String())
}

func TestSetString199291mod9991211391(t *testing.T) {
	mod := compatible_mod.NewInt(9991211391)
	initial := compatible.NewInt(199291) // in decimal
	i := NewInt(initial, mod)
	i.SetString("199291", "", 16) // in hex
	assert.Equal(t, "199291", strings.TrimPrefix(i.String(), "0000"))
}

func TestAdditions(t *testing.T) {
	mod := compatible_mod.NewInt(17)
	initial := compatible.NewInt(3)
	i := NewInt(initial, mod)
	i.Add(i, i)
	assert.Equal(t, "06", i.String()) // 6
	i.Add(i, i)
	assert.Equal(t, "0c", i.String()) // 12
	i.Add(i, i)
	assert.Equal(t, "07", i.String()) // 24 mod 17 = 7
	i.Add(i, i)
	assert.Equal(t, "0e", i.String()) // 14
	i.Add(i, i)
	assert.Equal(t, "0b", i.String()) // 28 mod 17 = 11
}

func TestSubtraction(t *testing.T) {
	mod := compatible_mod.NewInt(171)
	initial := compatible.NewInt(33)
	initialMinus := compatible.NewInt(100)
	i := NewInt(initial, mod)
	minus := NewInt(initialMinus, mod)
	i.Sub(i, minus)
	assert.Equal(t, "68", i.String()) // 33 - 100 mod 171 = 104 = 6 * 16 + 8
}

func TestMultiplication(t *testing.T) {
	mod := compatible_mod.NewInt(171)
	initial := compatible.NewInt(33)
	initialMul := compatible.NewInt(100)
	i := NewInt(initial, mod)
	mul := NewInt(initialMul, mod)
	i.Mul(i, mul)
	assert.Equal(t, "33", i.String()) // 3300 mod 171 = 51 = 16 * 3 + 3
}

func TestDivision(t *testing.T) {
	mod := compatible_mod.NewInt(181)
	initial := compatible.NewInt(51)
	initialDiv := compatible.NewInt(100)
	i := NewInt(initial, mod)
	div := NewInt(initialDiv, mod)
	i.Div(i, div)
	assert.Equal(t, "35", i.String()) // 51 / 100 mod 181 = [53]10 = [35]16
}

func TestComparisons(t *testing.T) {
	mod := compatible_mod.NewInt(171)
	numbers := []int64{0, 1, 13, 100, 21, 170, 110, 85, 35, 42}

	for i, n1 := range numbers {
		initial1 := compatible.NewInt(n1)
		i1 := NewInt(initial1, mod)

		for j, n2 := range numbers {
			initial2 := compatible.NewInt(n2)
			i2 := NewInt(initial2, mod)

			cmp := i1.Cmp(i2)

			if i == j {
				assert.Equal(t, 0, cmp, "Same numbers should be equal: ", n1, n2)
			} else if n1 > n2 {
				assert.Equal(t, 1, cmp, "First number should be greater", n1, n2)
			} else {
				assert.Equal(t, -1, cmp, "First number should be smaller", n1, n2)
			}
		}
	}
}

func TestSimpleInit(t *testing.T) {
	mod := compatible_mod.NewInt(171)
	initial := compatible.NewInt(33)
	i := NewInt(initial, mod)
	assert.Equal(t, "21", i.String())
}

func TestSimpleInit2(t *testing.T) {
	mod := compatible_mod.NewInt(171)
	initial := compatible.NewInt(33)
	i := NewInt(initial, mod)
	assert.Equal(t, "21", i.String())
	i.SetUint64(991)
	assert.Equal(t, "88", i.String()) // 991 mod 171 = 136 = 8*16 + 8
}

func TestPick(t *testing.T) {

	mod := compatible_mod.NewInt(171)
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	stream := cipher.NewCTR(block, make([]byte, block.BlockSize()))

	// Create multiple numbers and verify they're within bounds
	for i := 0; i < 10; i++ {
		initial := compatible.NewInt(0)
		num := NewInt(initial, mod)
		num.Pick(stream)
		// Verify number is within valid range (0 to modulo-1)
		assert.True(t, num.V.Sign() >= 0)
		assert.True(t, num.V.ToBigInt().Cmp(mod.ToBigInt()) < 0)
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
		{"100", "181", true},
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
		natValue := compatible.FromBigInt(bigValue, natMod)
		nat := NewInt(natValue, natMod)
		natInverse := NewInt(natValue, natMod).Inv(nat)
		hasNatInverse := natInverse != nil

		if hasBigInverse != tc.hasInverse {
			t.Errorf("big.Int ModInverse existence mismatch for %v mod %v: got %v, want %v",
				tc.value, tc.modulus, hasBigInverse, tc.hasInverse)
		}

		if hasNatInverse != tc.hasInverse {
			t.Errorf("Compatible ModInverse existence mismatch for %v mod %v: got %v, want %v",
				tc.value, tc.modulus, hasNatInverse, tc.hasInverse)
		}

		if tc.hasInverse {
			inverseAsBig := natInverse.(*Int).V.ToBigInt()
			if bigInverse.Cmp(inverseAsBig) != 0 {
				t.Errorf("ModInverse result mismatch for %v mod %v: got %v, want %v",
					tc.value, tc.modulus, inverseAsBig, bigInverse)
			}
		}
	}
}

func TestMultiplicationFullOrder(t *testing.T) {
	var twoExp256String = "115792089237316195423570985008687907853269984665640564039457584007913129639938"
	var twoExp256m1String = "115792089237316195423570985008687907853269984665640564039457584007913129639937"
	// twoExp256m1 is 2^256 - 1, used as the modulus for cofactor * primeOrder
	var twoExp256m1, _ = new(compatible.Int).SetString(twoExp256m1String, twoExp256String, 10)

	// todo, check the modulus for the multiplication here
	// order of the full group including the cofactor

	// prime order of base point = 2^252 + 27742317777372353535851937790883648493
	var primeOrder, _ = new(compatible.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", twoExp256m1String, 10)
	var cofactor = new(compatible.Int).SetUint64(8)
	var fullOrder = compatible.NewInt(0).Mul(primeOrder, cofactor, twoExp256m1.ToCompatibleMod())

	var bigFullOrder = fullOrder.ToBigInt()
	var bigCalculatedFullOrder = primeOrder.ToBigInt().Mul(primeOrder.ToBigInt(), cofactor.ToBigInt())
	fmt.Println(bigFullOrder, bigCalculatedFullOrder)
	assert.Equal(t, bigFullOrder, bigCalculatedFullOrder)
}

func TestNegativeInitialization(t *testing.T) {
	a := NewInt64(-1, compatible_mod.NewInt(97)) // mod 97
	assert.Equal(t, a.String(), "60")            // [96]10 = [60]16
}

func TestSetBytesBigBuf(t *testing.T) {
	buf := make([]byte, 32)
	buf[0] = 1
	mod := compatible_mod.NewInt(17)
	number := NewIntBytes(buf, mod, kyber.LittleEndian)

	fmt.Println(number.String())

}
