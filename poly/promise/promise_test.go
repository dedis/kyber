package promise

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

var suite = nist.NewAES128SHA256P256()
var altSuite = new(edwards.ExtendedCurve).Init(edwards.Param25519(), false)

var secretKey   = produceKeyPair()
var promiserKey = produceKeyPair()

var pt = 10
var r = 15
var numInsurers = 20

var insurerKeys = produceinsurerKeys()
var insurerList = produceinsurerList()

var basicPromise = new(Promise).ConstructPromise(secretKey, promiserKey, pt, r, insurerList)
var basicPromiseState = new(PromiseState).Init(*basicPromise)

func produceKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(suite, random.Stream)
	return keyPair
}

func produceAltKeyPair() *config.KeyPair {
	keyPair := new(config.KeyPair)
	keyPair.Gen(altSuite, random.Stream)
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
	sig := []byte("This is a test signature")
	p := new(PromiseSignature).init(suite, sig)
	if p.suite != suite {
		t.Error("Suite not properly initialized.")
	}
	if !reflect.DeepEqual(sig, p.signature) {
		t.Error("Signature not properly initialized.")
	}
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestPromiseSignatureUnMarshalInit(t *testing.T) {
	p := new(PromiseSignature).UnmarshalInit(suite)
	if p.suite != suite {
		t.Error("Suite not properly initialized.")
	}
}

// Verifies that PromiseSignature's marshalling code works
func TestPromiseSignatureBinaryMarshalling(t *testing.T) {
	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	sig := basicPromise.Sign(numInsurers-1, insurerKeys[numInsurers-1])
	encodedSig, err := sig.MarshalBinary()
	if err != nil || len(encodedSig) != sig.MarshalSize() {
		t.Fatal("Marshalling failed: ", err,
			len(encodedSig) != sig.MarshalSize())
	}

	decodedSig := new(PromiseSignature).UnmarshalInit(suite)
	err = decodedSig.UnmarshalBinary(encodedSig)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !sig.Equal(decodedSig) {
		t.Error("Decoded signature not equal to original")
	}
	if basicPromise.VerifySignature(numInsurers-1, decodedSig) != nil {
		t.Error("Decoded signature failed to be verified.")
	}

	// Tests MarshlTo and UnmarshalFrom
	sig2 := basicPromise.Sign(1, insurerKeys[1])
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := sig2.MarshalTo(bufWriter)
	if bytesWritter != sig2.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedSig2 := new(PromiseSignature).UnmarshalInit(suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedSig2.UnmarshalFrom(bufReader)
	if bytesRead != sig2.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if sig2.MarshalSize() != decodedSig2.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			sig2.MarshalSize(), decodedSig2.MarshalSize())
	}
	if !sig2.Equal(decodedSig2) {
		t.Error("PromiseSignature read does not equal original")
	}
	if basicPromise.VerifySignature(1, decodedSig2) != nil {
		t.Error("Read signature failed to be verified.")
	}

}

// Verifies that Equal properly works for PromiseSignature objects
func TestPromiseSignatureEqual(t *testing.T) {
	sig := []byte("This is a test")
	p := new(PromiseSignature).init(suite, sig)
	if !p.Equal(p) {
		t.Error("PromiseSignature should equal itself.")
	}

	// Error cases
	p2 := new(PromiseSignature).init(nil, sig)
	if p.Equal(p2) {
		t.Error("PromiseSignature's differ in suite.")
	}
	p2 = new(PromiseSignature).init(suite, nil)
	if p.Equal(p2) {
		t.Error("PromiseSignature's differ in signature.")
	}
}

// Verifies that Init properly initalizes a new BlameProof object
func TestBlameProofInit(t *testing.T) {
	proof := []byte("This is a test")
	sig := []byte("This too is a test")
	p := new(PromiseSignature).init(suite, sig)
	bp := new(BlameProof).init(suite, promiserKey.Public, proof, p)
	if suite != bp.suite {
		t.Error("Suite not properly initialized.")
	}
	if !bp.diffieKey.Equal(promiserKey.Public) {
		t.Error("Diffie-Hellman key not properly initialized.")
	}
	if !reflect.DeepEqual(bp.diffieKeyProof, proof) {
		t.Error("Diffie-Hellman proof not properly initialized.")
	}
	if !p.Equal(&bp.signature) {
		t.Error("PromisSignature not properly initialized.")
	}
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestBlameProofUnMarshalInit(t *testing.T) {
	bp := new(BlameProof).UnmarshalInit(suite)
	if bp.suite != suite {
		t.Error("BlameProof not properly initialized.")
	}
}

// Verifies that Equal properly works for PromiseSignature objects
func TestBlameProofEqual(t *testing.T) {
	p := new(PromiseSignature).init(suite, []byte("Test"))
	bp := new(BlameProof).init(suite, promiserKey.Public, []byte("Test"), p)
	if !bp.Equal(bp) {
		t.Error("BlameProof should equal itself.")
	}

	// Error cases
	bp2 := new(BlameProof).init(nil, promiserKey.Public, []byte("Test"), p)
	if bp.Equal(bp2) {
		t.Error("BlameProof differ in key suites.")
	}
	bp2 = new(BlameProof).init(suite, suite.Point().Base(), []byte("Test"), p)
	if bp.Equal(bp2) {
		t.Error("BlameProof differ in diffie-keys.")
	}
	bp2 = new(BlameProof).init(suite, promiserKey.Public, []byte("Differ"), p)
	if bp.Equal(bp2) {
		t.Error("BlameProof differ in hash proof.")
	}
	p2 := new(PromiseSignature).init(suite, []byte("Differ"))
	bp2 = new(BlameProof).init(suite, promiserKey.Public, []byte("Test"), p2)
	if bp.Equal(bp2) {
		t.Error("BlameProof differ in signatures.")
	}
}

// Verifies that BlameProof's marshalling methods work properly.
func TestBlameProofBinaryMarshalling(t *testing.T) {
	// Create a bad promise object. That a blame proof would succeed.
	promise := new(Promise).ConstructPromise(secretKey, promiserKey, pt, r, insurerList)
	badKey := insurerKeys[numInsurers-1]
	diffieBase := promise.suite.Point().Mul(promiserKey.Public, badKey.Secret)
	diffieSecret := promise.diffieHellmanSecret(diffieBase)
	badShare := promise.suite.Secret().Add(badKey.Secret, diffieSecret)
	promise.secrets[0] = badShare

	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	bp, _ := promise.Blame(0, insurerKeys[0])
	encodedBp, err := bp.MarshalBinary()
	if err != nil || len(encodedBp) != bp.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedBp := new(BlameProof).UnmarshalInit(suite)
	err = decodedBp.UnmarshalBinary(encodedBp)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !bp.Equal(decodedBp) {
		t.Error("Decoded BlameProof not equal to original")
	}
	if bp.MarshalSize() != decodedBp.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			bp.MarshalSize(), decodedBp.MarshalSize())
	}
	if promise.VerifyBlame(0, decodedBp) != nil {
		t.Error("Decoded BlameProof failed to be verified.")
	}

	// Tests MarshlTo and UnmarshalFrom
	bp2, _ := basicPromise.Blame(0, insurerKeys[0])
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := bp2.MarshalTo(bufWriter)
	if bytesWritter != bp2.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedBp2 := new(BlameProof).UnmarshalInit(suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedBp2.UnmarshalFrom(bufReader)
	if bytesRead != bp2.MarshalSize() || errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if bp2.MarshalSize() != decodedBp2.MarshalSize() {
		t.Error("MarshalSize of decoded and original differ: ",
			bp2.MarshalSize(), decodedBp2.MarshalSize())
	}
	if !bp2.Equal(decodedBp2) {
		t.Error("BlameProof read does not equal original")
	}
	if promise.VerifyBlame(0, decodedBp2) != nil {
		t.Error("Decoded BlameProof failed to be verified.")
	}

}

// Verifies that ConstructPromise properly initalizes a new Promise struct
func TestPromiseConstructPromise(t *testing.T) {
	// Verify that a promise can be initialized properly.
	promise := new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)

	if promise.id != secretKey.Public.String() {
		t.Error("id not initialized properly")
	}
	if promiserKey.Suite != promise.suite {
		t.Error("suite not initialized properly")
	}
	if secretKey.Suite != promise.suite {
		t.Error("suite not initialized properly")
	}
	if promise.t != pt {
		t.Error("t not initialized properly")
	}
	if promise.r != r {
		t.Error("r not initialized properly")
	}
	if promise.n != numInsurers {
		t.Error("n not initialized properly")
	}
	if !promise.pubKey.Equal(promiserKey.Public) {
		t.Error("Public Key not initialized properly")
	}
	if len(promise.secrets) != numInsurers {
		t.Error("Secrets array not initialized properly")
	}
	for i := 0; i < promise.n; i++ {
		if !insurerList[i].Equal(promise.insurers[i]) {
			t.Error("Public key for insurer not added:", i)
		}
		diffieBase := promise.suite.Point().Mul(insurerList[i],
			promiserKey.Secret)
		diffieSecret := promise.diffieHellmanSecret(diffieBase)
		share := promise.suite.Secret().Sub(promise.secrets[i], diffieSecret)
		if !promise.pubPoly.Check(i, share) {
			t.Error("Polynomial Check failed for share ", i)
		}
	}

	// Error handling
	// Check that ConstructPromise panics if n < t
	test := func() {
		defer deferTest(t, "ConstructPromise should have panicked.")
		new(Promise).ConstructPromise(secretKey, promiserKey, 2, r,
			[]abstract.Point{promiserKey.Public})
	}
	test()

	// Check that r is reset properly when r < t.
	test = func() {
		defer deferTest(t, "ConstructPromise should have panicked.")
		new(Promise).ConstructPromise(secretKey, promiserKey, pt, pt-1,
			insurerList)
	}
	test()

	// Check that r is reset properly when r > n.
	test = func() {
		defer deferTest(t, "ConstructPromise should have panicked.")
		new(Promise).ConstructPromise(secretKey, promiserKey, pt, numInsurers+1,
			insurerList)
	}
	test()

	// Check that ConstructPromise panics if the keys are of different suites
	test = func() {
		defer deferTest(t, "ConstructPromise should have panicked.")
		new(Promise).ConstructPromise(produceAltKeyPair(), promiserKey, pt, r,
			insurerList)
	}
	test()
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestPromiseUnMarshalInit(t *testing.T) {
	p := new(Promise).UnmarshalInit(suite)
	if p.suite != suite {
		t.Error("Suite not properly initialized.")
	}
}

// Tests that PromiseVerify properly rules out invalidly constructed Promise's
func TestPromiseVerifyPromise(t *testing.T) {
	if basicPromise.VerifyPromise(promiserKey.Public) != nil {
		t.Error("Promise is valid")
	}

	// Error handling
	promise := new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.t = promise.n + 1
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: t > n")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.t = promise.r + 1
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: t > r")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.r = promise.n + 1
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: n > r")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.pubKey = insurerList[0]
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: the public key is wrong")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.insurers = []abstract.Point{}
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: insurers list is the wrong length")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = []abstract.Secret{}
	if promise.VerifyPromise(promiserKey.Public) == nil {
		t.Error("Promise is invalid: secrets list is the wrong length")
	}
}

// Verifies that UnMarshalInit properly initalizes for unmarshalling
func TestPromiseGetId(t *testing.T) {
	if basicPromise.GetId() != secretKey.Public.String() {
		t.Error("Wrong id returned.")
	}
}

// Tests that encrypting a secret with a diffie-hellman shared secret and then
// decrypting it succeeds.
func TestPromiseDiffieHellmanEncryptDecrypt(t *testing.T) {
	// key2 and promiserKey will be the two parties. The secret they are
	// sharing is the private key of secretKey
	key2 := produceKeyPair()

	diffieBaseBasic := basicPromise.suite.Point().Mul(key2.Public,
		promiserKey.Secret)
	diffieSecret    := basicPromise.diffieHellmanSecret(diffieBaseBasic)
	encryptedSecret := basicPromise.suite.Secret().Add(secretKey.Secret, diffieSecret)

	diffieBaseKey2 := basicPromise.suite.Point().Mul(promiserKey.Public,
		key2.Secret)
	diffieSecret    = basicPromise.diffieHellmanSecret(diffieBaseKey2)
	secret := basicPromise.suite.Secret().Sub(encryptedSecret, diffieSecret)

	if !secret.Equal(secretKey.Secret) {
		t.Error("Diffie-Hellman encryption/decryption failed.")
	}
}

// Tests that insurers can properly verify their shares. Makes sure that
// verification fails if the proper credentials are not supplied (aka Diffie-
// Hellman decryption failed).
func TestPromiseVerifyShare(t *testing.T) {
	if basicPromise.VerifyShare(0, insurerKeys[0]) != nil {
		t.Error("The share should have been verified")
	}

	// Error handling
	if basicPromise.VerifyShare(-1, insurerKeys[0]) == nil {
		t.Error("The share should not have been valid. Index is negative.")
	}
	if basicPromise.VerifyShare(basicPromise.n, insurerKeys[0]) == nil {
		t.Error("The share should not have been valid. Index >= n")
	}
	if basicPromise.VerifyShare(numInsurers-1, insurerKeys[0]) == nil {
		t.Error("Share should be invalid. Index and Public Key did not match.")
	}
}

// Verify that the promise can produce a valid signature and then verify it.
// In short, all signatures produced by the sign method should be accepted.
func TestPromiseSignAndVerify(t *testing.T) {
	sig := basicPromise.Sign(0, insurerKeys[0])
	if basicPromise.VerifySignature(0, sig) != nil {
		t.Error("Signature failed to be validated")
	}
}

// Produces a bad signature that has a malformed approve message
func produceSigWithBadMessage() *PromiseSignature {
	set := anon.Set{insurerKeys[0].Public}
	approveMsg := "Bad message"
	digSig := anon.Sign(insurerKeys[0].Suite, random.Stream, []byte(approveMsg),
		set, nil, 0, insurerKeys[0].Secret)
	return new(PromiseSignature).init(insurerKeys[0].Suite, digSig)
}

// Verify that mallformed signatures are not accepted.
func TestPromiseVerifySignature(t *testing.T) {
	// Fail if the signature is not the specially formatted approve message.
	if basicPromise.VerifySignature(0, produceSigWithBadMessage()) == nil {
		t.Error("Signature has a bad message and should be rejected.")
	}

	//Error Handling
	// Fail if a valid signature is applied to the wrong share.
	sig := basicPromise.Sign(0, insurerKeys[0])
	if basicPromise.VerifySignature(numInsurers-1, sig) == nil {
		t.Error("Signature is for the wrong share.")
	}
	// Fail if index is negative
	if basicPromise.VerifySignature(-1, sig) == nil {
		t.Error("Error: Index < 0")
	}
	// Fail if index >= n
	if basicPromise.VerifySignature(basicPromise.n, sig) == nil {
		t.Error("Error: Index >= n")
	}
	// Should return false if passed nil
	sig.signature = nil
	if basicPromise.VerifySignature(0, sig) == nil {
		t.Error("Error: Signature is nil")
	}
}

// Verify that insurer secret shares can be revealed properly and verified.
func TestPromiseRevealShareAndShareVerify(t *testing.T) {
	promiseShare := basicPromise.RevealShare(0, insurerKeys[0])
	if basicPromise.VerifyRevealedShare(0, promiseShare) != nil {
		t.Error("The share should have been marked as valid")
	}

	// Error Handling
	if basicPromise.VerifyRevealedShare(-1, promiseShare) == nil {
		t.Error("The index provided is too low.")
	}
	if basicPromise.VerifyRevealedShare(numInsurers, promiseShare) == nil {
		t.Error("The index provided is too high.")
	}
	// Ensures the public polynomial fails when the share provided doesn't
	// match the index.
	if basicPromise.VerifyRevealedShare(2, promiseShare) == nil {
		t.Error("The share provided is not for the index.")
	}
}

// Verify that insurers can properly create and verify blame proofs
func TestPromiseBlameAndVerify(t *testing.T) {

	// Create a bad promise object. Create a new secret that will fail the
	// the public polynomial check.
	promise := new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	badKey := insurerKeys[numInsurers-1]
	diffieBase := promise.suite.Point().Mul(promiserKey.Public,
		badKey.Secret)
	diffieSecret := promise.diffieHellmanSecret(diffieBase)
	badShare := promise.suite.Secret().Add(badKey.Secret, diffieSecret)
	promise.secrets[0] = badShare

	validProof, err := promise.Blame(0, insurerKeys[0])
	if err != nil {
		t.Fatal("Blame failed to be properly constructed")
	}
	if promise.VerifyBlame(0, validProof) != nil {
		t.Error("The proof is valid and should be accepted.")
	}

	// Error handling
	if promise.VerifyBlame(-10, validProof) == nil {
		t.Error("The i index is below 0")
	}
	if promise.VerifyBlame(numInsurers, validProof) == nil {
		t.Error("The i index is at or above n")
	}

	goodPromiseShare, _ := basicPromise.Blame(0, insurerKeys[0])
	if basicPromise.VerifyBlame(0, goodPromiseShare) == nil {
		t.Error("Invalid blame: the share is actually good.")
	}
	badProof, _ := basicPromise.Blame(0, insurerKeys[0])
	badProof.diffieKeyProof = []byte("Invalid zero-knowledge proof")
	if basicPromise.VerifyBlame(0, badProof) == nil {
		t.Error("Invalid blame. Bad Diffie-Hellman key proof.")
	}
	badSignature, _ := basicPromise.Blame(0, insurerKeys[0])
	badSignature.signature = *promise.Sign(1, insurerKeys[1])
	if basicPromise.VerifyBlame(0, badSignature) == nil {
		t.Error("Invalid blame. The signature is bad.")
	}
}

// Verifies that Equal properly works for Promise structs
func TestPromiseEqual(t *testing.T) {
	// Make sure promise equals basicPromise to make the error cases
	// below valid (if promise never equals basicPromise, error cases are
	// trivially true). Secrets and the public polynomial must be set
	// equal in each case to make sure that promise and basicPromise are
	// equal.
	promise := new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	if !basicPromise.Equal(promise) {
		t.Error("Promises should be equal.")
	}

	// Error cases
	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.suite = nil
	if basicPromise.Equal(promise) {
		t.Error("The suite's are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.n = 0
	if basicPromise.Equal(promise) {
		t.Error("The n's are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.t = 0
	if basicPromise.Equal(promise) {
		t.Error("The t's are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.r = 0
	if basicPromise.Equal(promise) {
		t.Error("The r's are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.pubKey = suite.Point().Base()
	if basicPromise.Equal(promise) {
		t.Error("The public keys are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	if basicPromise.Equal(promise) {
		t.Error("The public polynomials are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.secrets = basicPromise.secrets
	promise.pubPoly = basicPromise.pubPoly
	promise.insurers = make([]abstract.Point, promise.n, promise.n)
	copy(promise.insurers, insurerList)
	promise.insurers[numInsurers-1] = suite.Point().Base()
	if basicPromise.Equal(promise) {
		t.Error("The insurers array are not equal")
	}

	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt,
		r, insurerList)
	promise.pubPoly = basicPromise.pubPoly
	if basicPromise.Equal(promise) {
		t.Error("The secrets array are not equal")
	}
}

// Verifies that Promise's marshalling functions work properly
func TestPromiseBinaryMarshalling(t *testing.T) {

	// Tests BinaryMarshal, BinaryUnmarshal, and MarshalSize
	encodedP, err := basicPromise.MarshalBinary()
	if err != nil || len(encodedP) != basicPromise.MarshalSize() {
		t.Fatal("Marshalling failed: ", err)
	}

	decodedP := new(Promise).UnmarshalInit(suite)
	err = decodedP.UnmarshalBinary(encodedP)
	if err != nil {
		t.Fatal("UnMarshalling failed: ", err)
	}
	if !basicPromise.Equal(decodedP) {
		t.Error("Decoded Promise not equal to original")
	}

	// Tests MarshlTo and UnmarshalFrom
	bufWriter := new(bytes.Buffer)
	bytesWritter, errs := basicPromise.MarshalTo(bufWriter)

	if bytesWritter != basicPromise.MarshalSize() || errs != nil {
		t.Fatal("MarshalTo failed: ", bytesWritter, err)
	}

	decodedP2 := new(Promise).UnmarshalInit(suite)
	bufReader := bytes.NewReader(bufWriter.Bytes())
	bytesRead, errs2 := decodedP2.UnmarshalFrom(bufReader)
	if bytesRead != decodedP2.MarshalSize() ||
		basicPromise.MarshalSize() != decodedP2.MarshalSize() ||
		errs2 != nil {
		t.Fatal("UnmarshalFrom failed: ", bytesRead, errs2)
	}
	if basicPromise.MarshalSize() != decodedP2.MarshalSize() {
		t.Error("MarshalSize's differ: ", basicPromise.MarshalSize(),
			decodedP2.MarshalSize())
	}
	if !basicPromise.Equal(decodedP2) {
		t.Error("Promise read does not equal original")
	}
}

// Verifies that Init properly initalizes a new PromiseState object
func TestPromiseStateInit(t *testing.T) {
	promiseState := new(PromiseState).Init(*basicPromise)
	if !basicPromise.Equal(&promiseState.Promise) {
		t.Error("Promise not properly initialized")
	}
	if len(promiseState.signatures) != numInsurers {
		t.Error("Signatures array not properly initialized")
	}
}

// Verify that PromiseState can properly add signatures
func TestPromiseStateAddSignature(t *testing.T) {
	promiseState := new(PromiseState).Init(*basicPromise)
	for i := 0; i < numInsurers; i++ {
		sig := promiseState.Promise.Sign(i, insurerKeys[i])
		promiseState.AddSignature(i, sig)
		if !sig.Equal(promiseState.signatures[i]) {
			t.Error("Signature failed to be added")
		}
	}
}

// Verify that PromiseState can add blames.
func TestPromiseStateAddBlame(t *testing.T) {
	promiseState := new(PromiseState).Init(*basicPromise)
	for i := 0; i < numInsurers; i++ {
		bproof, _ := promiseState.Promise.Blame(i, insurerKeys[i])
		promiseState.AddBlameProof(i, bproof)
		if !bproof.Equal(promiseState.blames[i]) {
			t.Error("Blame failed to be added")
		}
	}
}

// Verify PromiseState's PromiseCertify function
func TestPromiseStatePromiseCertified(t *testing.T) {
	promise := new(Promise).ConstructPromise(secretKey, promiserKey,
		pt, r, insurerList)
	promiseState := new(PromiseState).Init(*promise)

	// Once enough signatures have been added, the Promise should remain
	// certified.
	for i := 0; i < numInsurers; i++ {
		promiseState.AddSignature(i,
			promiseState.Promise.Sign(i, insurerKeys[i]))

		// Insure that bad BlameProof structs do not cause the Promise
		// to be considered uncertified.
		bproof, _ := promiseState.Promise.Blame(i, insurerKeys[i])
		promiseState.AddBlameProof(i, bproof)

		err := promiseState.PromiseCertified(promiserKey.Public)
		if i < r-1 && err == nil {
			t.Error("Not enough signtures have been added yet", i, r)
		} else if i >= r-1 && err != nil {
			t.Error("Promise should be valid now.")
			t.Error(promiseState.PromiseCertified(promiserKey.Public))
		}
	}

	// Error handling

	// If the Promise fails VerifyPromise, it should be uncertified even if
	// everything else is okay.
	promiseState.Promise.n = 0
	if err := promiseState.PromiseCertified(promiserKey.Public); err == nil {
		t.Error("The Promise is malformed and should be uncertified")
	}

	// Make sure that one valid BlameProof makes the Promise forever
	// uncertified
	promise = new(Promise).ConstructPromise(secretKey, promiserKey, pt, r, insurerList)
	promiseState = new(PromiseState).Init(*promise)
	promise.secrets[0] = promise.suite.Secret()
	for i := 0; i < numInsurers; i++ {
		promiseState.AddSignature(i,
			promiseState.Promise.Sign(i, insurerKeys[i]))
		bproof, _ := promiseState.Promise.Blame(i, insurerKeys[i])
		promiseState.AddBlameProof(i, bproof)
		if promiseState.PromiseCertified(promiserKey.Public) == nil {
			t.Error("A valid BlameProof makes this uncertified")
		}
	}
}

// Tests all the string functions. Simply calls them to make sure they return.
func TestString(t *testing.T) {
	sig := basicPromise.Sign(0, insurerKeys[0])
	sig.String()

	bp, _ := basicPromise.Blame(0, insurerKeys[0])
	bp.String()

	basicPromise.String()
}
