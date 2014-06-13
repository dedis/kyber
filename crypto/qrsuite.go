package crypto

import (
	"hash"
	"math/big"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

type qrsuite struct {
	SchnorrGroup
} 

// SHA256 hash function
func (s qrsuite) HashLen() int { return sha256.Size }
func (s qrsuite) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s qrsuite) KeyLen() int { return 16 }
func (s qrsuite) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}


func NewAES128SHA256QR512() *qrsuite {
	p,_ := new(big.Int).SetString("10198267722357351868598076141027380280417188309231803909918464305012113541414604537422741096561285049775792035177041672305646773132014126091142862443826263", 10)
	q,_ := new(big.Int).SetString("5099133861178675934299038070513690140208594154615901954959232152506056770707302268711370548280642524887896017588520836152823386566007063045571431221913131", 10)
	r := new(big.Int).SetInt64(2)
	g := new(big.Int).SetInt64(4)

	suite := new(qrsuite)
	suite.SetParams(p,q,r,g)
	return suite
}

func NewAES128SHA256QR1024() *qrsuite {
	suite := new(qrsuite)
	suite.QuadraticResidueGroup(1024, RandomStream) // XXX
	return suite
}

