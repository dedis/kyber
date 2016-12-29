package ph


import (
	"github.com/dedis/crypto/abstract"
)

type PH struct {
	encKey abstract.Scalar
	decKey abstract.Scalar
	suite  abstract.Suite
}

func NewPH(suite abstract.Suite) *PH {
	ph := &PH{
		suite: suite,
	}
	ph.createKeys()
	return ph
}

//Create encryption and decryption keys
func (c *PH) createKeys() {

	enckey := c.suite.Scalar().Pick(random.Stream) // ephemeral private key

	for !c.suite.Scalar().Gcd(enckey).Equal(c.suite.Scalar().One()) {
		enckey = c.suite.Scalar().Pick(random.Stream)
	}

	c.encKey = enckey
	c.decKey = c.suite.Scalar().Inv(enckey)

}

//Decrypt with Pohlig Hellman, output is a string
func (c *PH) PHDecrypt(cipher abstract.Point) (
	message string) {

	var bytemessage []byte

	S := c.suite.Point().Mul(cipher, c.decKey)
	bytemessage, _ = S.Data()
	message = string(bytemessage)

	return

}

//Encrypt with Pohlig Hellman, input is []byte
func (c *PH) PHEncrypt(message []byte) (
	S abstract.Point) {

	M, _ := c.suite.Point().Pick(message, random.Stream)
	S = c.suite.Point().Mul(M, c.encKey)
	return
}

//Decrypt with Pohlig Hellman, output is a point
func (c *PPSI) PartialPHDecrypt(cipher abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(cipher, c.decKey)
	return

}

//Encrypt with Pohlig Hellman, input is a point
func (c *PPSI) PartialPHEncrypt(M abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(M, c.encKey)
	return
}

func Example_PHEncryption() {

	var c1 *PH
	suite := nist.NewAES128SHA256P256()
	c1 = NewPPSI(suite)
	message := []byte("Pohlig Hellman")
	cipher := c1.PHEncrypt(message)
	encmessage := c1.PHDecrypt(cipher)

	if string(message) != string(encmessage) {
		panic("decryption produced wrong output: " + string(encmessage))
	}
	println("Decryption succeeded: " + string(encmessage))

}
