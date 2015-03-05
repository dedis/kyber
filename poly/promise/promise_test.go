package promise

import (
	"bytes"
	"testing"
	"reflect"

	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

var keySuite   = nist.NewAES128SHA256P256()
var shareGroup = new(edwards.ExtendedCurve).Init(edwards.Param25519(), false)

var promiserKey = produceKeyPair()

var numInsurers = 20

var insurerKeys = produceinsurerKeys()
var insurerList = produceinsurerList()

var pt = 10
var r  = 15
var basicPromise = new(Promise).Init(promiserKey, pt, r, insurerList)
var basicPromiseState = new(PromiseState).Init(basicPromise)

func produceKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(keySuite, random.Stream)
	return keyPair
}

func produceinsurerKeys() []*config.KeyPair {
	newArray := make([]*config.KeyPair, numInsurers, numInsurers)
	for i := 0; i < numInsurers; i++ {
		newArray[i] = produceKeyPair()
	}
	return newArray
}

func produceinsurerList() []abstract.Point {
	newArray := make([]abstract.Point, numInsurers, numInsurers)
	for i := 0; i < numInsurers; i++ {
		newArray[i] = insurerKeys[i].Public
	}
	return newArray
}

// Tests that check whether a method panics can use this funcition
func deferTest(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Error(message)
	}
}

// Verifies that Init properly initalizes a new PromiseSignature object
func TestPromiseSignatureInit(t *testing.T) {
	i := 20 
	sig := []byte("This is a test")
	p := new(PromiseSignature).Init(i, keySuite, sig)
	
	if p.pi != i || p.suite != keySuite || !reflect.DeepEqual(sig, p.signature) {
		t.Error("PromiseSignature not properly initialized.")
	}
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestPromiseSignatureUnMarshalInit(t *testing.T) {
	p := new(PromiseSignature).UnMarshalInit(keySuite)
	if p.suite != keySuite {
		t.Error("PromiseSignature not properly initialized.")
	}
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestPromiseSignatureBinaryMarshalling(t *testing.T) {
	
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	sig := basicPromise.Sign(numInsurers-1, insurerKeys[numInsurers-1])
	encodedSig, err := sig.MarshalBinary()
	if err != nil || len(encodedSig) != sig.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}
	
	decodedSig := new(PromiseSignature).UnMarshalInit(keySuite)
	err = decodedSig.UnmarshalBinary(encodedSig)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !sig.Equal(decodedSig) {
		t.Error("Decoded signature not equal to original")
	}
	
	// Tests MarshlTo and UnmarshalFrom
	sig2 := basicPromise.Sign(1, insurerKeys[1])
	bufWriter := new(bytes.Buffer)
	
	bytesWritter, errs := sig2.MarshalTo(bufWriter)
	
	if bytesWritter != sig2.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}
	
	decodedSig2 := new(PromiseSignature).UnMarshalInit(keySuite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedSig2.UnmarshalFrom(bufReader)
	if bytesRead != sig2.MarshalSize() ||
	   sig2.MarshalSize() != decodedSig2.MarshalSize() ||
	   errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if !sig2.Equal(decodedSig2) {
		t.Error("Signature read does not equal original")
	}
}



// Verifies that Equal properly works for PromiseSignature objects
func TestPromiseSignatureEqual(t *testing.T) {
	sig := []byte("This is a test")
	p := new(PromiseSignature).Init(29, keySuite, sig)
	
	if !p.Equal(p) {
		t.Error("PromiseSignature should equal itself.")
	}
	
	// Error cases
	p2 := new(PromiseSignature).Init(20, keySuite, sig)	
	if p.Equal(p2) {
		t.Error("PromiseSignature differ in pi.")
	}

	p2 = new(PromiseSignature).Init(29, nil, sig)	
	if p.Equal(p2) {
		t.Error("PromiseSignature differ in suite.")
	}

	p2 = new(PromiseSignature).Init(29, keySuite, nil)	
	if p.Equal(p2) {
		t.Error("PromiseSignature differ in signature.")
	}
}

// Verifies that Init properly initalizes a new Promise object
func TestPromiseInit(t *testing.T) {

	// Verify that a promise can be initialized properly.
	promise := new(Promise).Init(promiserKey, pt, r, insurerList)
		
	if promiserKey.Suite.String() != promise.shareSuite.String() ||
	   promise.t != pt || promise.r != r || promise.n != numInsurers ||
	   promise.pubKey != promiserKey.Public ||
	   len(promise.secrets)    != numInsurers {
		t.Error("Invalid initialization")	   
	}

	for i := 0 ; i < promise.n; i++ {
	
	   	if !insurerList[i].Equal(promise.insurers[i]) {
	   		t.Error("Public key for insurer not added:", i)
	   	}

		diffieBase := promise.shareSuite.Point().Mul(insurerList[i], promiserKey.Secret)
		share := promise.diffieHellmanDecrypt(promise.secrets[i], diffieBase)
		if !promise.pubPoly.Check(i, share) {
			t.Error("Polynomial Check failed for share ", i)
		}
	}
	
	// Error handling
	
	// Check that Init panics if n < t
	test := func() {
		defer deferTest(t, "Init should have panicked.")
		new(Promise).Init(promiserKey, pt, r,
			[]abstract.Point{promiserKey.Public})
	}

	test()
	
	
	// Check that r is reset properly when r < t.
	promise = new(Promise).Init(promiserKey, pt, pt-20, insurerList)
	if promise.r < pt || promise.r > numInsurers {
		t.Error("Invalid r allowed for r < t.")
	}


	// Check that r is reset properly when r > n.
	promise = new(Promise).Init(promiserKey, pt, numInsurers+20, insurerList)
	if  promise.r < pt || promise.r > numInsurers {
		t.Error("Invalid r allowed for r > n.")
	}
}

// Tests that GetId returns the Promise Id and the Id is unique.
func TestPromiseGetId(t *testing.T) {
	if basicPromise.id != basicPromise.GetId() {
		t.Error("Id not returned properly.")
	}
	
	// Make sure two promises made at similar times are different.
	promise  := new(Promise).Init(promiserKey, pt, r, insurerList)
	promise2 := new(Promise).Init(promiserKey, pt, r, insurerList)

	if promise.GetId() == promise2.GetId() {
		t.Error("Id's should be different for different policies")
	}
}


// Tests that encrypting a secret with a diffie-hellman shared key and then
// decrypting it succeeds.
func TestPromiseDiffieHellmanEncryptDecrypt(t *testing.T) {
	// key2 and promiserKey will be the two parties. The secret they are
	// share is the private key of secretKey
	key2      := produceKeyPair()
	secretKey := produceKeyPair()
	
	diffieBaseBasic := basicPromise.shareSuite.Point().Mul(key2.Public, promiserKey.Secret)
	encryptedSecret := basicPromise.diffieHellmanEncrypt(secretKey.Secret, diffieBaseBasic)


	diffieBaseKey2 := basicPromise.shareSuite.Point().Mul(promiserKey.Public, key2.Secret)
	secret := basicPromise.diffieHellmanDecrypt(encryptedSecret, diffieBaseKey2)

	if !secret.Equal(secretKey.Secret) {
		t.Error("Diffie-Hellman encryption/decryption failed.")
	}
}

// Tests that insurers can properly verify their share. Make sure that
// verification fails if the proper credentials are not supplied (aka Diffie-
// Hellman decryption failed).
func TestPromiseShareVerify(t *testing.T) {
	if !basicPromise.VerifyShare(0, insurerKeys[0]) {
		t.Error("The share should have been verified")
	}

	// Make sure the wrong index and key pair fail.
	if basicPromise.VerifyShare(numInsurers-1, insurerKeys[0]) {
		t.Error("The share should not have been valid.")
	}
}

// Verify that the promise can produce a valid signature and then verify it.
// In short, all signatures produced by the sign method should be accepted.
func TestPromiseSignAndVerify(t *testing.T) {
	for i := 0 ; i < numInsurers; i++ {
		sig := basicPromise.Sign(i, insurerKeys[i])
		if !basicPromise.VerifySignature(sig) {
			t.Error("Signature failed to be validated")
		}
	}
}

// Produces a bad signature that has a malformed approve message
func produceSigWithBadMessage() *PromiseSignature {
	set        := anon.Set{insurerKeys[0].Public}
	approveMsg := "Bad message"
	digSig     := anon.Sign(insurerKeys[0].Suite, random.Stream, []byte(approveMsg),
		     set, nil, 0, insurerKeys[0].Secret)
		     
	return new(PromiseSignature).Init(0, insurerKeys[0].Suite, digSig)
}

// Produces a bad signature that says it is for the wrong index.
func produceSigWithBadIndex() *PromiseSignature {
	sig    := basicPromise.Sign(0, insurerKeys[0])
	sig.pi = numInsurers-1   
	return sig
}

// Verify that mallformed signatures are not accepted.
func TestPromiseSignVerify(t *testing.T) {
	// Fail if the signature is not the specially formatted approve message.
	if basicPromise.VerifySignature(produceSigWithBadMessage()) {
		t.Error("Signature has a bad message and should be rejected.")
	}

	// Fail if a valid signature is applied to the wrong share.
	if basicPromise.VerifySignature(produceSigWithBadIndex()) {
		t.Error("Signature is for the wrong share.")
	}
}

// Verify that insurer secret shares can be revealed properly and verified.
func TestPromiseRevealShareAndShareVerify(t *testing.T) {

	promiseShare := basicPromise.RevealShare(0, insurerKeys[0])
	if !basicPromise.PromiseShareVerify(promiseShare) {
		t.Error("The share should have been marked as valid")
	}
	
	// Error Handling
	badShare := basicPromise.RevealShare(0, insurerKeys[0])
	badShare.i = -10
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The share is invalid and has too low an index.")
	}


	badShare = basicPromise.RevealShare(0, insurerKeys[0])
	badShare.i = numInsurers + 20
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The share is invalid and has too high an index.")
	}
	
	badShare = basicPromise.RevealShare(0, insurerKeys[0])
	badShare.share = insurerKeys[0].Secret
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The PromiseShare is invalid with a bad share.")
	}
}

// Verify that insurers can properly create and verify blame proofs
func TestPromiseBlameAndVerify(t *testing.T) {

	// Create a bad promise object. Create a new secret that will fail the
	// the public polynomial check. 
	promise := new(Promise).Init(promiserKey, pt, r, insurerList)
	badKey := insurerKeys[numInsurers-1]
	
	diffieBase := promise.shareSuite.Point().Mul(promiserKey.Public, badKey.Secret)
	badShare := promise.diffieHellmanEncrypt(badKey.Secret, diffieBase)
	
	promise.secrets[0] = badShare


	validProof := promise.Blame(0, insurerKeys[0])
	if !promise.BlameVerify(validProof) {
		t.Error("The proof is valid and should be accepted.")
	}

	// Error handling
	goodPromiseShare := basicPromise.Blame(0, insurerKeys[0])
	if basicPromise.BlameVerify(goodPromiseShare) {
		t.Error("Invalid blame: the share is actually good.")
	}

	badProof := basicPromise.Blame(0, insurerKeys[0])
	badProof.i = -10
	if basicPromise.BlameVerify(badProof) {
		t.Error("The i index is below 0")
	}

	badProof = basicPromise.Blame(0, insurerKeys[0])
	badProof.i = numInsurers +20
	if basicPromise.BlameVerify(badProof) {
		t.Error("The i index is below above n")
	}

	badProof = basicPromise.Blame(0, insurerKeys[0])
	badProof.share = insurerKeys[0].Secret
	if basicPromise.BlameVerify(badProof) {
		t.Error("The PromiseShare is invalid with a bad share.")
	}
}


// Verifies that Init properly initalizes a new PromiseState object
func TestPromiseStateInit(t *testing.T) {

	promiseState := new(PromiseState).Init(basicPromise)
	
	if //!basicPromise.Equal(promiseState.Promise) || <-- Once I write Equal
	   len(promiseState.signatures) != numInsurers {
		t.Error("Invalid initialization")	   
	}
}

// Verify that Promise and PromiseState can produce a valid signature and then verify it.
func TestPromiseStateAddSignature(t *testing.T) {

	promise := new(Promise).Init(promiserKey, pt, r, insurerList)
	promiseState := new(PromiseState).Init(promise)

	// Error Checking. Make sure bad signatures are not added.
	badSig := produceSigWithBadMessage()
	if promiseState.AddSignature(badSig) ||
	   promiseState.signatures[0] != nil {
		t.Error("Signature should not have been added")
	}

	badSig = produceSigWithBadIndex()
	if promiseState.AddSignature(badSig) ||
	   promiseState.signatures[numInsurers-1] != nil {
		t.Error("Signature should not have been added")
	}

	// Verify that all validly produced signatures can be added.
	for i := 0 ; i < numInsurers; i++ {
		sig := promise.Sign(i, insurerKeys[i])
		
		if !promiseState.AddSignature(sig) ||
		   !sig.Equal(promiseState.signatures[i]) {
			t.Error("Signature failed to be added")
		}
	}
}


// Verify that once r signatures have been added, the promise becomes valid.
func TestPromiseStatePromiseVerify(t *testing.T) {

	promise := new(Promise).Init(promiserKey, pt, r, insurerList)
	promiseState := new(PromiseState).Init(promise)

	for i := 0 ; i < numInsurers; i++ {
		if i < r && promiseState.VerifyPromise() {
			t.Error("Not enough signtures have been added yet", i, r)
		} else if i >= r && !promiseState.VerifyPromise() {
			t.Error("Promise should be valid now.")
		}

		promiseState.AddSignature(promise.Sign(i, insurerKeys[i]))
	}
}

