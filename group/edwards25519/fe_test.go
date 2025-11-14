package edwards25519

import (
	"go.dedis.ch/kyber/v4/compatible"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

func Test_feToBnEdgeCase(t *testing.T) {
	fieldElems := []fieldElement{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		{1, -1, 1, -1, 1, -1, 1, -1, 1, -1},
		{123312, 54, 36467, 64465, 23524, 235, 234532, 643, 8975, 74654},
		{12323312, -54, 356477, -69965, -23538, 32235, -233492, -643, 348975, 9174654},
	}

	expectedInts := []string{
		"0",
		"1",
		"17254366098375493971863732723163371589623513702264028891549843847118849",
		"57896042893221536725152487541740382065544292822329234251877658128066988212206",
		"128810743174081990895079563873863294634158893429674322163950556506889511344",
		"15830283690864357567092656272836221286294103082314903268964457249510342265328",
	}

	actualBn := big.NewInt(0)
	for i, c := range fieldElems {
		feToBn(actualBn, &c)
		assert.Equal(t, expectedInts[i], actualBn.String())
	}
}

func Test_feBnConversionRandom(t *testing.T) {
	seed := "feToBn"
	rng := blake2xb.New([]byte(seed))

	// Prepare 2 random numbers
	var fe0 fieldElement
	var fe1 fieldElement
	var fe2 fieldElement
	l := 32
	p0 := make([]byte, l)
	p1 := make([]byte, l)
	p2 := make([]byte, l)

	s, err := rng.Read(p0)
	assert.NoError(t, err)
	assert.Equal(t, s, l)

	s, err = rng.Read(p1)
	assert.NoError(t, err)
	assert.Equal(t, s, l)

	s, err = rng.Read(p2)
	assert.NoError(t, err)
	assert.Equal(t, s, l)

	b0 := big.NewInt(0).SetBytes(p0)
	b0 = b0.Mod(b0, prime)

	b1 := big.NewInt(0).SetBytes(p1)
	b1 = b1.Mod(b1, prime)

	b2 := big.NewInt(0).SetBytes(p2)
	b2 = b1.Mod(b2, prime)

	// Convert compatible.Int to fieldElement
	feFromBn(&fe0, b0)
	feFromBn(&fe1, b1)
	feFromBn(&fe2, b2)

	// If we convert correctly, we should get the same result:
	// (fe0 + fe1)*fe2 == (b0 + b1) * b2
	var feRes fieldElement
	var bExp *compatible.Int

	feAdd(&feRes, &fe0, &fe1)
	feMul(&feRes, &feRes, &fe2)

	bExp = big.NewInt(0).Add(b0, b1)
	bExp = big.NewInt(0).Mul(bExp, b2)
	bExp = bExp.Mod(bExp, prime)

	// Final conversion to compare the results
	bActual := big.NewInt(0)
	feToBn(bActual, &feRes)

	assert.Equal(t, bExp.Cmp(bActual), 0)
}
