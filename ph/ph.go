package ppsi_crypto_utils

import (
	"github.com/dedis/crypto/elgamal"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
	"math/rand"
)

type PPSI struct {
	EncryptedSets [][]map[int]abstract.Point
	ids           int
	encKey        abstract.Scalar
	decKey        abstract.Scalar
	suite         abstract.Suite
	publics       []abstract.Point
	private       abstract.Scalar
}

func NewPPSI(suite abstract.Suite, private abstract.Scalar, publics []abstract.Point, ids int) *PPSI {
	ppsi := &PPSI{
		suite:   suite,
		private: private,
		publics: publics,
	}
	ppsi.ids = ids
	ppsi.createKeys()
	return ppsi
}

func NewPPSI2(suite abstract.Suite, publics []abstract.Point, ids int) *PPSI {
	ppsi := &PPSI{
		suite: suite,

		publics: publics,
	}
	ppsi.ids = ids
	ppsi.createKeys()
	return ppsi
}

func (c *PPSI) initPPSI(numPhones int, ids int) {
	//		c.EncryptedPhoneSet =  make([]map[int]abstract.Point, numPhones)
	c.ids = ids

}

//Given several sets of messags, elgamal encrypt each one multiple times-"ids" times, each time with the
//public key of a diffrent user
func (c *PPSI) EncryptPhones(setsToEncrypt [][]string, ids int) [][]map[int]abstract.Point {

	c.EncryptedSets = make([][]map[int]abstract.Point, ids)
	for i := 0; i < len(setsToEncrypt); i++ {
		out := c.EncryptionOneSetOfPhones(setsToEncrypt[i], ids)
		c.EncryptedSets[i] = out
		//	 fmt.Printf("%v\n",   c.EncryptedSets[i])
	}

	return c.EncryptedSets
}

func (c *PPSI) Shuffle(src []map[int]abstract.Point) []map[int]abstract.Point {

	dst := make([]map[int]abstract.Point, len(src))
	perm := rand.Perm(len(src))
	for i, v := range perm {
		dst[v] = src[i]
	}

	return dst
}

//Given one messaege, elgamal encrypt it multiple times-"ids" times, each time with
//the public key of a different user
func (c *PPSI) MultipleElgEncryption(message string, ids int) (
	cipher map[int]abstract.Point) {

	cipher = make(map[int]abstract.Point)
	messageByte := []byte(message)

	K, C, _ := elgamal.ElGamalEncrypt(c.suite, c.publics[0], messageByte)
	cipher[0] = K
	cipher[-1] = C

	for v := 1; v < ids; v++ {
		data := cipher[-1]
		K, C, _ := elgamal.PartialElGamalEncrypt(c.suite, c.publics[v], data)
		cipher[v] = K
		cipher[-1] = C

	}

	return cipher

}

//Given one set of messages, elgamal encrypt each one multiple times-"ids" times,
//each time with the public key of a different user
func (c *PPSI) EncryptionOneSetOfPhones(set []string, ids int) (
	EncryptedPhoneSet []map[int]abstract.Point) {

	EncryptedPhoneSet = make([]map[int]abstract.Point, len(set))
	for v := 0; v < len(set); v++ {
		cipher := c.MultipleElgEncryption(set[v], ids)
		EncryptedPhoneSet[v] = cipher

	}

	return

}

//Given one set of ciphers, for each cipher, performs an elgamal decryption with the user "id" private key,
//and Phoilg Hellman encryption with the user's "id" PH key
func (c *PPSI) DecryptElgEncrptPH(set []map[int]abstract.Point, id int) (
	UpdatedSet []map[int]abstract.Point) {

	UpdatedSet = make([]map[int]abstract.Point, len(set))
	UpdatedSet = set

	for i := 0; i < len(set); i++ {
		cipher := set[i]
		K := cipher[id]

		C := cipher[-1]

		resElg, _ := elgamal.PartialElGamalDecrypt(c.suite, c.private, K, C)

		resPH := c.PHEncrypt(resElg)

		UpdatedSet[i][-1] = resPH

		for j := 0; j < c.ids; j++ {
			res2PH := c.PHEncrypt(cipher[j])
			UpdatedSet[i][j] = res2PH
		}

	}
	UpdatedSet = c.Shuffle(UpdatedSet)
	return
}

//Extracts the ciphers themselves from a map to a slice
func (c *PPSI) ExtractPHEncryptions(set []map[int]abstract.Point) (
	encryptedPH []abstract.Point) {
	encryptedPH = make([]abstract.Point, len(set))

	for i := 0; i < len(set); i++ {
		cipher := set[i]
		encryptedPH[i] = cipher[-1]

	}
	return
}

//Performs a partial pohig hellman decryption-the input is a message which is encrypted by 2 or more users' keys,
//and the output is the message after one layer of decryption was removed and it is still encrypted
//by 1 or more user's keys
func (c *PPSI) DecryptPH(set []abstract.Point) (UpdatedSet []abstract.Point) {

	UpdatedSet = make([]abstract.Point, len(set))
	UpdatedSet = set

	for i := 0; i < len(UpdatedSet); i++ {
		resPH := c.PHDecrypt(UpdatedSet[i])
		UpdatedSet[i] = resPH
	}

	return
}

//Extracts the plains  to a slice
func (c *PPSI) ExtractPlains(set []abstract.Point) (
	plain []string) {
	plain = make([]string, len(set))

	var byteMessage []byte
	var message string

	for i := 0; i < len(set); i++ {
		byteMessage, _ = set[i].Data()
		message = string(byteMessage)
		plain[i] = message

	}

	return

}

//Create encryption and decryption keys
func (c *PPSI) createKeys() {

	enckey := c.suite.Scalar().Pick(random.Stream)

	for !c.suite.Scalar().Gcd(enckey).Equal(c.suite.Scalar().One()) {
		enckey = c.suite.Scalar().Pick(random.Stream)
	}

	c.encKey = enckey
	c.decKey = c.suite.Scalar().Inv(enckey)

}

//Decrypt with PH, input is a point
func (c *PPSI) PHDecrypt(cipher abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(cipher, c.decKey)
	return

}

//Encrypt with PH, input is a point
func (c *PPSI) PHEncrypt(M abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(M, c.encKey)
	return
}

func test_utils() {
	suite := nist.NewAES128SHA256P256()
	var c1 *PPSI
	var c2 *PPSI
	var c3 *PPSI

	var rep *PPSI

	a := suite.Scalar().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	b := suite.Scalar().Pick(random.Stream)
	B := suite.Point().Mul(nil, b)
	c := suite.Scalar().Pick(random.Stream)
	C := suite.Point().Mul(nil, c)

	d := suite.Scalar().Pick(random.Stream)
	//		D := suite.Point().Mul(nil, d)

	set11 := []string{"543323345", "543323045", "843323345"}

	publics := []abstract.Point{A, B, C}
	private1 := a
	private2 := b
	private3 := c
	private4 := d

	c1 = NewPPSI(suite, private1, publics, 3)
	c2 = NewPPSI(suite, private2, publics, 3)
	c3 = NewPPSI(suite, private3, publics, 3)
	rep = NewPPSI(suite, private4, publics, 3)

	//	var set1,set2,set3 []map[int]abstract.Point
	var set4, set5, set6, set7 []abstract.Point
	var set8 []string
	var set0 []map[int]abstract.Point

	set0 = rep.EncryptionOneSetOfPhones(set11, 3)

	set1 := c1.DecryptElgEncrptPH(set0, 0)
	set2 := c2.DecryptElgEncrptPH(set1, 1)
	set3 := c3.DecryptElgEncrptPH(set2, 2)
	set4 = c3.ExtractPHEncryptions(set3)
	//fmt.Printf("%v\n",   set4)

	set5 = c3.DecryptPH(set4)
	set6 = c1.DecryptPH(set5)
	set7 = c2.DecryptPH(set6)

	set8 = c2.ExtractPlains(set7)
	println("Decryption : " + set8[0])
	println("Decryption : " + set8[1])
	println("Decryption : " + set8[2])

}
