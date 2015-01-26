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
