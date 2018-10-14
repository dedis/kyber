package daga

import (
	"github.com/dedis/kyber"
	"math/rand"
	"testing"
)

// TODO use assert
func TestSchnorrSign(t *testing.T) {
	priv := suite.Scalar().Pick(suite.RandomStream())

	//Normal execution
	sig, err := SchnorrSign(suite, priv, []byte("Test String"))
	if err != nil || sig == nil {
		t.Error("Cannot execute signature")
	}

	//Empty public key
	sig, err = SchnorrSign(suite, nil, []byte("Test String"))
	if err == nil || sig != nil {
		t.Error("Empty public key is accepted")
	}

	//Empty message
	sig, err = SchnorrSign(suite, priv, nil)
	if err == nil || sig != nil {
		t.Error("Empty message is accepted")
	}
}

func TestSchnorrVerify(t *testing.T) {
	//Correct signature
	priv := suite.Scalar().Pick(suite.RandomStream())
	msg := []byte("Test String")
	sig, _ := SchnorrSign(suite, priv, msg)

	//Normal signature
	check := SchnorrVerify(suite, suite.Point().Mul(priv, nil), msg, sig)
	if check != nil {
		t.Error("Cannot verify signatures")
	}

	//Incorrect message
	var fake []byte
	copy(fake, msg)
	fake = append(fake, []byte("A")...)
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), fake, sig)
	if check == nil {
		t.Error("Wrong check: Message edited")
	}

	//Signature modification
	newsig := append([]byte("A"), sig...)
	newsig = newsig[:len(sig)]
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), msg, newsig)
	if check == nil {
		t.Error("Wrong check: signature changed")
	}

	//Empty public key
	check = SchnorrVerify(suite, nil, msg, sig)
	if check == nil {
		t.Error("Wrong check: empty public key")
	}

	//Empty message
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), nil, sig)
	if check == nil {
		t.Error("Wrong check: empty message")
	}

	//0 length message
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), []byte{}, sig)
	if check == nil {
		t.Error("Wrong check: 0 length message")
	}

	//Empty signature
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), msg, nil)
	if check == nil {
		t.Error("Wrong check: empty signature")
	}

	//0 length signature
	check = SchnorrVerify(suite, suite.Point().Mul(priv, nil), msg, []byte{})
	if check == nil {
		t.Error("Wrong check: 0 length signature")
	}
}

func TestToBytes(t *testing.T) {
	c := rand.Intn(10) + 1
	s := rand.Intn(10) + 1
	_, _, context, _ := GenerateTestContext(suite, c, s)
	data, err := context.ToBytes()
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert valid context to bytes")
	}
}

func TestPointArrayToBytes(t *testing.T) {
	length := rand.Intn(10) + 1
	var Points []kyber.Point
	for i := 0; i < length; i++ {
		Points = append(Points, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	}
	data, err := PointArrayToBytes(Points)
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert Point Array to bytes")
	}
}

func TestScalarArrayToBytes(t *testing.T) {
	length := rand.Intn(10) + 1
	var Scalars []kyber.Scalar
	for i := 0; i < length; i++ {
		Scalars = append(Scalars, suite.Scalar().Pick(suite.RandomStream()))
	}
	data, err := ScalarArrayToBytes(Scalars)
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert Scalar Array to bytes")
	}
}
