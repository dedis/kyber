package edwards25519

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

func Test_feToBnZero(t *testing.T) {
	var f0 fieldElement
	feZero(&f0)

	b0 := big.NewInt(0)
	feToBn(b0, &f0)

	assert.Equal(t, big.NewInt(0).Cmp(b0), 0)
}

func Test_feBnConversionRandom(t *testing.T) {
	seed := "feToBn"
	rng := blake2xb.New([]byte(seed))

	// Prepare 2 random numbers
	var fe0 fieldElement
	var fe1 fieldElement
	l := len(fe0) * 4
	p0 := make([]byte, l)
	p1 := make([]byte, l)

	s, err := rng.Read(p0)
	assert.NoError(t, err)
	assert.Equal(t, s, l)

	s, err = rng.Read(p1)
	assert.NoError(t, err)
	assert.Equal(t, s, l)

	b0 := big.NewInt(0).SetBytes(p0)
	b0 = b0.Mod(b0, prime)

	b1 := big.NewInt(0).SetBytes(p1)
	b0 = b1.Mod(b1, prime)

	// Convert big.Int to fieldElement
	feFromBn(&fe0, b0)
	feFromBn(&fe1, b1)

	// If we convert correctly, we should get the same result:
	// fe0 + fe1 == b0 + b1
	var feRes fieldElement
	var bExp *big.Int

	feAdd(&feRes, &fe0, &fe1)
	bExp = big.NewInt(0).Add(b0, b1)
	bExp = bExp.Mod(bExp, prime)

	// Final conversion to compare the results
	bActual := big.NewInt(0)
	feToBn(bActual, &feRes)

	assert.Equal(t, bExp.Cmp(bActual), 0)
}
