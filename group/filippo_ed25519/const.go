package filippo_ed25519

import (
	filippo_ed25519 "filippo.io/edwards25519"
	"math/big"
)

var primeOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
var cofactor = new(big.Int).SetInt64(8)
var fullOrder = new(big.Int).Mul(primeOrder, cofactor)

var filippoPrimeOrderScalar = setBigInt(primeOrder)
var filippoCofactorScalar = setBigInt(cofactor)
var filippoNullPoint = Point{filippo_ed25519.NewIdentityPoint()}

var marshalPointID = [16]byte{'f', 'i', 'l', 'i', 'p', 'p', 'o', '_', 'e', 'd', '.', 'p', 'o', 'i', 'n', 't'}
