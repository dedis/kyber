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

var numGuardians = 20

var guardianKeys = produceGuardianKeys()
var guardianList = produceGuardianList()

var pt = 10
var r  = 15
var basicPromise = new(Promise).Init(promiserKey, pt, r, guardianList)

func produceKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(keySuite, random.Stream)
	return keyPair
}

func produceGuardianKeys() []*config.KeyPair {
	newArray := make([]*config.KeyPair, numGuardians, numGuardians)
	for i := 0; i < numGuardians; i++ {
		newArray[i] = produceKeyPair()
	}
	return newArray
}

func produceGuardianList() []abstract.Point {
	newArray := make([]abstract.Point, numGuardians, numGuardians)
	for i := 0; i < numGuardians; i++ {
		newArray[i] = guardianKeys[i].Public
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
	sig := basicPromise.Sign(numGuardians-1, guardianKeys[numGuardians-1])
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
	sig2 := basicPromise.Sign(1, guardianKeys[1])
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
	promise := new(Promise).Init(promiserKey, pt, r, guardianList)
		
	if promiserKey.Suite.String() != promise.shareSuite.String() ||
	   promise.t != pt || promise.r != r || promise.n != numGuardians ||
	   promise.pubKey != promiserKey.Public ||
	   len(promise.signatures) != numGuardians   ||
	   len(promise.secrets)    != numGuardians {
		t.Error("Invalid initialization")	   
	}

	for i := 0 ; i < promise.n; i++ {
	
	   	if !guardianList[i].Equal(promise.guardians[i]) {
	   		t.Error("Public key for guardian not added:", i)
	   	}

		diffieBase := promise.shareSuite.Point().Mul(guardianList[i], promiserKey.Secret)
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
	promise = new(Promise).Init(promiserKey, pt, pt-20, guardianList)
	if promise.r < pt || promise.r > numGuardians {
		t.Error("Invalid r allowed for r < t.")
	}


	// Check that r is reset properly when r > n.
	promise = new(Promise).Init(promiserKey, pt, numGuardians+20, guardianList)
	if  promise.r < pt || promise.r > numGuardians {
		t.Error("Invalid r allowed for r > n.")
	}
}

// Tests that GetId returns the Promise Id and the Id is unique.
func TestPromiseGetId(t *testing.T) {
	if basicPromise.id != basicPromise.GetId() {
		t.Error("Id not returned properly.")
	}
	
	// Make sure two promises made at similar times are different.
	promise  := new(Promise).Init(promiserKey, pt, r, guardianList)
	promise2 := new(Promise).Init(promiserKey, pt, r, guardianList)

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

// Tests that guardians can properly verify their share. Make sure that
// verification fails if the proper credentials are not supplied (aka Diffie-
// Hellman decryption failed).
func TestPromiseShareVerify(t *testing.T) {
	if !basicPromise.VerifyShare(0, guardianKeys[0]) {
		t.Error("The share should have been verified")
	}

	// Make sure the wrong index and key pair fail.
	if basicPromise.VerifyShare(numGuardians-1, guardianKeys[0]) {
		t.Error("The share should not have been valid.")
	}
}

// Verify that the promise can produce a valid signature and then verify it.
// In short, all signatures produced by the sign method should be accepted.
func TestPromiseSignAndVerify(t *testing.T) {
	for i := 0 ; i < numGuardians; i++ {
		sig := basicPromise.Sign(i, guardianKeys[i])
		if !basicPromise.VerifySignature(sig) {
			t.Error("Signature failed to be validated")
		}
	}
}

// Produces a bad signature that has a malformed approve message
func produceSigWithBadMessage() *PromiseSignature {
	set        := anon.Set{guardianKeys[0].Public}
	approveMsg := "Bad message"
	digSig     := anon.Sign(guardianKeys[0].Suite, random.Stream, []byte(approveMsg),
		     set, nil, 0, guardianKeys[0].Secret)
		     
	return new(PromiseSignature).Init(0, guardianKeys[0].Suite, digSig)
}

// Produces a bad signature that says it is for the wrong index.
func produceSigWithBadIndex() *PromiseSignature {
	sig    := basicPromise.Sign(0, guardianKeys[0])
	sig.pi = numGuardians-1   
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

// Verify that the promise can produce a valid signature and then verify it.
func TestPromiseAddSignature(t *testing.T) {

	promise := new(Promise).Init(promiserKey, pt, r, guardianList)

	// Error Checking. Make sure bad signatures are not added.
	badSig := produceSigWithBadMessage()
	if promise.AddSignature(badSig) ||
	   promise.signatures[0] != nil {
		t.Error("Signature should not have been added")
	}

	badSig = produceSigWithBadIndex()
	if promise.AddSignature(badSig) ||
	   promise.signatures[numGuardians-1] != nil {
		t.Error("Signature should not have been added")
	}

	// Verify that all validly produced signatures can be added.
	for i := 0 ; i < numGuardians; i++ {
		sig := promise.Sign(i, guardianKeys[i])
		
		if !promise.AddSignature(sig) ||
		   !sig.Equal(promise.signatures[i]) {
			t.Error("Signature failed to be added")
		}
	}
}


// Verify that once r signatures have been added, the promise becomes valid.
func TestPromiseVerify(t *testing.T) {

	promise := new(Promise).Init(promiserKey, pt, r, guardianList)

	for i := 0 ; i < numGuardians; i++ {
		if i < r && promise.VerifyPromise() {
			t.Error("Not enough signtures have been added yet", i, r)
		} else if i >= r && !promise.VerifyPromise() {
			t.Error("Promise should be valid now.")
		}

		promise.AddSignature(promise.Sign(i, guardianKeys[i]))
	}
}

// Verify that guardian secret shares can be revealed properly and verified.
func TestPromiseRevealShareAndShareVerify(t *testing.T) {

	promiseShare := basicPromise.RevealShare(0, guardianKeys[0])
	if !basicPromise.PromiseShareVerify(promiseShare) {
		t.Error("The share should have been marked as valid")
	}
	
	// Error Handling
	badShare := basicPromise.RevealShare(0, guardianKeys[0])
	badShare.i = -10
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The share is invalid and has too low an index.")
	}


	badShare = basicPromise.RevealShare(0, guardianKeys[0])
	badShare.i = numGuardians + 20
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The share is invalid and has too high an index.")
	}
	
	badShare = basicPromise.RevealShare(0, guardianKeys[0])
	badShare.share = guardianKeys[0].Secret
	if basicPromise.PromiseShareVerify(badShare) {
		t.Error("The PromiseShare is invalid with a bad share.")
	}
}

// Verify revealed shares can be added properly and then reconstructed
func TestPromiseShareAdditionAndReconstruction(t *testing.T) {

	promise := new(Promise).Init(promiserKey, pt, r, guardianList)

	for i := 0 ; i < numGuardians; i++ {
	
		share := promise.RevealShare(i, guardianKeys[i])
		
		if !promise.PromiseShareVerify(share) {
			t.Fatal("The share should be valid.")
		}
		
		promise.AddRevealedSecret(share)
		
		if i < pt-1 && promise.CanReconstructSecret() {
			t.Fatal("Not enough shares to reconstruct yet.")
		}

		if i >= pt-1 && !promise.CanReconstructSecret() {
			t.Fatal("The secret should be reconstructable now.")
		} 
		
		if i >= pt-1 && promise.CanReconstructSecret(){
			secret := promise.ReconstructSecret()
			
			if !secret.Equal(promiserKey.Secret) {
				t.Fatal("Reconstructed secret not equal to original.")
			}
		}
	}
}
