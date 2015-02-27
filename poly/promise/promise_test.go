package promise

import (
	"testing"

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

// Tests that checks whether a method panics can use this funcition
func deferTest(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Error(message)
	}
}

// Verifies that Init properly initalizes a new Promise object
func TestPromiseInit(t *testing.T) {

	// Verify that a promise can be initialized properly.
	pt := 10
	r := 15

	promise := new(Promise).Init(promiserKey, pt, r, guardianList)
		
	if promiserKey.Suite.String() != promise.shareGroup.String() ||
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

		// TODO: Figure out how to decrypt each secret and verify that
		// it checks out okay.
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
	promise := new(Promise).Init(promiserKey, pt, r, guardianList)
	promise2 := new(Promise).Init(promiserKey, pt, r, guardianList)

	if basicPromise.id != basicPromise.GetId() {
		t.Error("Id not returned properly.")
	}
	
	if promise.GetId() == promise2.GetId() {
		t.Error("Id's should be different for different policies")
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
func produceSigWithBadMessage() PromiseSignature {
	set        := anon.Set{guardianKeys[0].Public}
	approveMsg := "Bad message"
	digSig     := anon.Sign(guardianKeys[0].Suite, random.Stream, []byte(approveMsg),
		     set, nil, 0, guardianKeys[0].Secret)
		     
	return PromiseSignature{pi: 0, suite: guardianKeys[0].Suite, signature: digSig}
}

// Produces a bad signature that says it is for the wrong index.
func produceSigWithBadIndex() PromiseSignature {
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

	// Error Checking. Make sure bad signatures are not added.
	badSig := produceSigWithBadMessage()
	if basicPromise.AddSignature(badSig) ||
	   !basicPromise.signatures[0].isUninitialized() {
		t.Error("Signature should not have been added")
	}

	badSig = produceSigWithBadIndex()
	if basicPromise.AddSignature(badSig) ||
	   !basicPromise.signatures[numGuardians-1].isUninitialized() {
		t.Error("Signature should not have been added")
	}

	// Verify that all validly produced signatures can be added.
	for i := 0 ; i < numGuardians; i++ {
		sig := basicPromise.Sign(i, guardianKeys[i])
		
		if !basicPromise.AddSignature(sig) ||
		   !sig.Equal(basicPromise.signatures[i]) {
			t.Error("Signature failed to be added")
		}
	}
}
