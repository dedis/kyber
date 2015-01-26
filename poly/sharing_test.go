package poly

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

/* This file is a go testing suite for sharing.go. It provides
 * multiple test cases for ensuring that encryption schemes built
 * with this (such as Shamir secret sharing) are safe and secure.
 *
 * The tests can also server as a useful reference for how to work
 * with this library.
 */

var group abstract.Group = new(edwards.ExtendedCurve).Init(
	edwards.Param25519(), false)
var k int = 10
var n int = 20
var secret = group.Secret()
var point  = group.Point()

// Test that the Pick function creates unique polynomials and provides unique
// secrets.
func TestPriPolyPick_UniqueShares(t *testing.T) {

	testPoly1 := new(PriPoly).Pick(group, k, nil, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k, nil, random.Stream)
	testPoly3 := new(PriPoly).Pick(group, k, nil, random.Stream)

	if testPoly1.Equal(testPoly2) || testPoly1.Equal(testPoly3) ||
		testPoly2.Equal(testPoly3) {
		t.Error("Failed to create unique polynomials.")
	}

	if testPoly1.Secret().Equal(testPoly2.Secret()) ||
		testPoly1.Secret().Equal(testPoly3.Secret()) ||
		testPoly2.Secret().Equal(testPoly3.Secret()) {
		t.Error("Failed to create unique secrets.")
	}
}

// Test polynomials that are based on common secrets. Verify that
// unique polynomials are created but that the base secrets are all
// the same.
func TestPriPolyPick_CommonShares(t *testing.T) {

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly3 := new(PriPoly).Pick(group, k, secret, random.Stream)

	if testPoly1.Equal(testPoly2) || testPoly1.Equal(testPoly3) ||
		testPoly2.Equal(testPoly3) {
		t.Error("Failed to create unique polynomials.")
	}

	if !testPoly1.Secret().Equal(testPoly2.Secret()) ||
		!testPoly1.Secret().Equal(testPoly3.Secret()) ||
		!testPoly2.Secret().Equal(testPoly3.Secret()) {
		t.Error("Polynomials are expected to have the same secret.")
	}
}

// Verify that the Secret function works. If we give the polynomial a secret,
// it should return the same one.
func TestPriPolySecret(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)

	if !secret.Equal(testPoly.Secret()) {
		t.Error("The secret is expected to be the same one given to it.")
	}
}

// Verify that the equal function returns true for two polynomials that are
// the same
func TestPriPolyEqual_Same(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPolyCopy := testPoly

	if !testPoly.Equal(testPolyCopy) {
		t.Error("Polynomials are expected to be equal.")
	}
}

// Verify that the equal function returns false for two polynomials that are
// diffferent
func TestPriPolyEqual_Different(t *testing.T) {

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)

	if testPoly1.Equal(testPoly2) {
		t.Error("Polynomials are expected to be different.")
	}
}

// Verify that the equal function panics if the polynomials
// are of different degrees.
func TestPriPolyEqual_Error1(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k+10, secret, random.Stream)

	// This function should panic if the two polynomials are not of
	// the same degree. Hence if we reach the end of this function normally,
	// we should panic
	testPoly1.Equal(testPoly2)
}

// Verify that the equal function panics if the polynomials
// are of different groups.
func TestPriPolyEqual_Error2(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	tempGroup := new(edwards.ProjectiveCurve).Init(edwards.ParamE382(), false)

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(tempGroup, k, tempGroup.Secret(), random.Stream)

	// This function should panic if the two polynomials are not of
	// the same group. Hence if we reach the end of this function normally,
	// we should panic
	testPoly1.Equal(testPoly2)
}

// Verify that the equal function returns true for two polynomials that are
// the same
func TestPriPolyAdd_Success(t *testing.T) {

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)
	
	testAddedPoly := new(PriPoly).Add(testPoly1, testPoly2)

	for i := 0; i < k; i++ {
		if !testAddedPoly.s[i].Equal(
			testAddedPoly.g.Secret().Add(
				testPoly1.s[i],testPoly2.s[i])) {
			t.Error("Polynomials not added together properly.")
		}
	}
}


// Verify that the add function panics if the polynomials
// are of different degrees.
func TestPriPolyAdd_Error1(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k+10, secret, random.Stream)

	new(PriPoly).Add(testPoly1, testPoly2)
}

// Verify that the add function panics if the polynomials
// are of different groups.
func TestPriPolyAdd_Error2(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	tempGroup := new(edwards.ProjectiveCurve).Init(edwards.ParamE382(), false)

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(tempGroup, k, tempGroup.Secret(), random.Stream)

	new(PriPoly).Add(testPoly1, testPoly2)
}


// Verify that the string function returns a string representation of the
// polynomial. The test simply assures that the function exits successfully.
func TestPriPolyString(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	result := testPoly.String()
	t.Log(result)
}

// Tests the split and share function simultaneously.
// Splits a private polynomial and ensures that share
// i is the private polynomial evaluated at point i.
func TestPriSharesSplitShare(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, n)

	errorString := "Share %v should equal the polynomial evaluated at %v"

	for i := 0; i < n; i++ {
		if !testShares.Share(i).Equal(testPoly.Eval(i)) {
			t.Error(errorString, i, i)
		}
	}
}

// This verifies that Empty properly creates a fresh, empty private share.
func TestPriSharesEmpty(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, n)
	testShares.Empty(group, k+1, n+1)

	if group.String() != testShares.g.String() || testShares.k != k+1 ||
		len(testShares.s) != n+1 {
		t.Error("Empty failed to set the share object properly.")
	}

	for i := 0; i < n+1; i++ {
		if testShares.Share(i) != nil {
			t.Error("Share should be nil.")
		}
	}
}

// This verifies the SetShare function. It sets the share and then
// ensures that the share returned is as expected.
func TestPriSharesSetShare(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, n)
	testShares.Empty(group, k, n)

	testShares.SetShare(0, secret)
	if !secret.Equal(testShares.Share(0)) {
		t.Error("The share was not set properly.")
	}
}

// This verifies that the xCoord function can successfully
// create an array with k secrets from a PriShare with sufficient
// secrets.
func TestPriSharesxCoord_Success(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, k)

	x := testShares.xCoords()
	c := 0

	for i := 0; i < len(x); i++ {
		if x[i] != nil {
			c += 1
		}
	}

	if c < k {
		t.Error("Expected %v points to be made.", k)
	}
}

// Ensures that if we have k-1 shares, xCoord panics.
func TestPriSharesxCoord_Failure(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, k)
	testShares.s[0] = nil

	testShares.xCoords()
}

// Ensures that we can successfully reconstruct the secret if given k shares.
func TestPriSharesSecret_Success(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, k)

	result := testShares.Secret()

	if !secret.Equal(result) {
		t.Error("The secret failed to be reconstructed.")
	}
}

// Ensures that we fail to reconstruct the secret with too little shares.
func TestPriSharesSecret_Failure(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, k)
	testShares.s[0] = nil

	testShares.Secret()
}

// Tests the string function by simply verifying that it runs to completion.
func TestPriSharesString(t *testing.T) {
	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testShares := new(PriShares).Split(testPoly, k)
	result := testShares.String()

	t.Log(result)
}


// Tests the initialation function insuring it can create a public polynomial
// correctly.
func TestPubPolyInit(t *testing.T) {
	testPoly := new(PubPoly)
	testPoly.Init(group, k, point)
	if group.String() != testPoly.g.String() || //!point.Equal(testPoly.b) ||
	   k != len(testPoly.p) {
		t.Error("The public polynomial was not initialized properly.")   
	 }
}

// Tests the commit function to ensure it properly commits a private polynomial.
func TestPubPolyCommit(t *testing.T) {
	//testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	//testPubPoly := new(PubPoly)
	//testPubPoly.Init(group, k, point)
	
	//testPubPoly = testPubPoly.Commit(testPriPoly, point)

	//for i := 0; i < len(testPubPoly.p); i++ {
	//	if !point.Mul(point, testPriPoly.s[i]).Equal(testPubPoly.p[i]) {
	//		t.Error("PriPoly should be multiplied by the point")
	//	}
	//}
}

// Tests the commit to ensure it works with the standard base.
func TestPubPolyCommit_Nil(t *testing.T) {
	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPubPoly := new(PubPoly)
	testPubPoly.Init(group, k, nil)
	
	testPubPoly = testPubPoly.Commit(testPriPoly, nil)

	for i := 0; i < len(testPubPoly.p); i++ {
		if !point.Mul(nil, testPriPoly.s[i]).Equal(testPubPoly.p[i]) {
			t.Error("PriPoly should be multiplied by the point")
		}
	}
}

// Verifies the secret commit function returns the altered secret from the
// private polynomial.
func TestPubPolySecretCommit(t *testing.T) {
	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPubPoly := new(PubPoly)
	testPubPoly.Init(group, k, point)
	
	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
	//secretCommit := testPubPoly.SecretCommit()
	
	//if !point.Mul(point, testPriPoly.s[0]).Equal(secretCommit) {
	//	t.Error("The secret commit is not from the private secret")
	//}
}

// Encode a public polynomial and verify its length is as expected.
func TestPubPolyLen(t *testing.T) {
	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPubPoly := new(PubPoly)
	testPubPoly.Init(group, k, point)
	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
	if testPubPoly.Len() != len(testPubPoly.Encode()) {
		t.Error("The length should equal the length of the encoding")
	}
}


// Encode a public polynomial and then decode it.
func TestPubPolyEncodeDecode(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
//	decodePubPoly := new(PubPoly)
//	decodePubPoly.Init(group, k, point)
	
//	if err := decodePubPoly.Decode(testPubPoly.Encode()); err != nil ||
//		!decodePubPoly.Equal(testPubPoly) {
//		t.Error("Failed to encode/ decode properly.")
//	}
}

// Verify that encode fails if the group and point are not the same
// length (aka not from the same group in this case).
func TestPubPolyEncodeDecode_Failure1(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//      badPoint := new(edwards.ProjectiveCurve).Init(
//		edwards.ParamE382(), false).Point()
//	testPubPoly.Init(group, k, badPoint)
//	testPubPoly = testPubPoly.Commit(testPriPoly, badPoint)
	
//	testPubPoly.Encode());
}


// Verify the decoding/ encoding fails if the new polynomial is the wrong len.
func TestPubPolyEncodeDecode_Failure2(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
//	decodePubPoly := new(PubPoly)
//	decodePubPoly.Init(group, k+20, point)
	
//	if err := decodePubPoly.Decode(testPubPoly.Encode()); err == nil {
//		t.Error("Decode should fail.")
//	}
}

// Verify that the equal function returns true for two polynomials that are
// the same
func TestPubPolyEqual_Same(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
//
//	testPubPolyCopy := testPubPoly

//	if !testPubPoly.Equal(testPubPolyCopy) {
//		t.Error("Polynomials are expected to be equal.")
//	}
}

// Verify that the equal function returns false for two polynomials that are
// diffferent
func TestPubPolyEqual_Different(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testPriPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(group, k, point)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, point)

//	if testPubPoly1.Equal(testPubPoly2) {
//		t.Error("Polynomials are expected to be different.")
//	}
}

// Verify that the equal function panics if the polynomials
// are of different degrees.
func TestPubPolyEqual_Error1(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testPriPoly2 := new(PriPoly).Pick(group, k+10, secret, random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(group, k+10, point)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, point)

//	testPoly1.Equal(testPoly2)
}

// Verify that the equal function panics if the polynomials
// are of different groups.
func TestPubPolyEqual_Error2(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	group2 := new(edwards.ProjectiveCurve).Init(edwards.ParamE382(), false)
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testPriPoly2 := new(PriPoly).Pick(group2, k, secret, random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(group2, k, point)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, point)

//	testPoly1.Equal(testPoly2)
}

// Verify that the string function returns a string representation of the
// polynomial. The test simply assures that the function exits successfully.
func TestPubPolyString(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
//	result := testPoly.String()
//	t.Log(result)
}


// Verify that the equal function returns true for two polynomials that are
// the same
func TestPubPolyAdd_Success(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testPriPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(group, k, point)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, point)
	
//	testAddedPoly := new(PubPoly).Add(testPubPoly, testPriPoly2)

//	for i := 0; i < k; i++ {
//		if !testAddedPoly.p[i].Equal(
//			testAddedPoly.g.Point().Add(
//				testPoly1.p[i],testPoly2.p[i])) {
//			t.Error("Polynomials not added together properly.")
//		}
//	}
}


// Verify that the add function panics if the polynomials
// are of different degrees.
func TestPubPolyAdd_Error1(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testPriPoly2 := new(PriPoly).Pick(group, k+10, secret, random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(group, k+10, point)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, point)
	
//	new(PubPoly).Add(testPubPoly, testPriPoly2)

}

// Verify that the add function panics if the polynomials
// are of different groups.
func TestPubPolyAdd_Error2(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	tempGroup := new(edwards.ProjectiveCurve).Init(edwards.ParamE382(), false)

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	tempPoint := tempGroup.Point()
//
//	testPriPoly2 := new(PriPoly).Pick(tempGroup, k, tempGroup.Secret(), random.Stream)
//	testPubPoly2 := new(PubPoly)
//	testPubPoly2.Init(tempGroup.Secret(), k, tempPoint)
//	testPubPoly2 = testPubPoly.Commit(testPriPoly, tempPoint)
	
//	new(PubPoly).Add(testPubPoly, testPriPoly2)
}

// Verifies that the function correctly identifies a valid share.
func TestPubPolyCheck_True(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
//	testShares := new(PriShares).Split(testPoly, n)
	
//	if testPubPoly.Check(testShares.Share(1)) == false {
//		t.Error("The share should be accepted.")
//	}
}


// Verifies that the function correctly rejects an invalid share.
func TestPubPolyCheck_False(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
//	testPriPolyBad := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testSharesBad := new(PriShares).Split(testPriPolyBad, n)
	
//	if testPubPoly.Check(testSharesBad.Share(1)) == true {
//		t.Error("The share should be rejected.")
//	}
}


// Tests the split and share function simultaneously.
// Splits a public polynomial and ensures that share
// i is the public polynomial evaluated at point i.
func TestPubSharesSplitShare(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, n)

//	errorString := "Share %v should equal the polynomial evaluated at %v"

//	for i := 0; i < n; i++ {
//		if !testShares.Share(i).Equal(testPubPoly.Eval(i)) {
//			t.Error(errorString, i, i)
//		}
//	}
}

// This verifies the SetShare function. It sets the share and then
// ensures that the share returned is as expected.
func TestPubSharesSetShare(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)
	
//	newPoint := group.Point()

//	testShares := new(PubShares).Split(testPubPoly, n)
//	testShares.SetShare(0, newPoint)
//	if !newPoint.Equal(testShares.Share(0)) {
//		t.Error("The share was not set properly.")
//	}
}

// This verifies that the xCoord function can successfully
// create an array with k secrets from a PubShare with sufficient
// secrets.
func TestPubSharesxCoord_Success(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, k)

//	x := testShares.xCoords()
//	c := 0

//	for i := 0; i < len(x); i++ {
//		if x[i] != nil {
//			c += 1
//		}
//	}

//	if c < testShares.k {
//		t.Error("Expected %v points to be made.", k)
//	}
}

// Ensures that if we have k-1 shares, xCoord panics.
func TestPubSharesxCoord_Failure(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, k)
//	testShares.p[0] = nil

//	testShares.xCoords()
}

// Ensures that we can successfully reconstruct the secret if given k shares.
func TestPubSharesSecret_Success(t *testing.T) {

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, k)

//	result := testShares.SecretCommit()

	// TODO figure out exactly what this point should be.
	
	//if !point.Equal(result) {
	//	t.Error("The point failed to be reconstructed.")
	//}
}

// Ensures that we fail to reconstruct the secret with too little shares.
func TestPubSharesSecret_Failure(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.FailNow()
		}
	}()

//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, k)
//	testShares.p[0] = nil

//	result := testShares.SecretCommit()
}

// Tests the string function by simply verifying that it runs to completion.
func TestPubSharesString(t *testing.T) {
//	testPriPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
//	testPubPoly := new(PubPoly)
//	testPubPoly.Init(group, k, point)
	
//	testPubPoly = testPubPoly.Commit(testPriPoly, point)

//	testShares := new(PubShares).Split(testPubPoly, k)
//	result := testShares.String()

//	t.Log(result)
}

