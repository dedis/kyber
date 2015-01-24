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
var secret = group.Secret()

// Test that the Pick function creates unique polynomials and provides unique
// secrets.
func TestPick_UniqueShares(t *testing.T) {

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
func TestPick_CommonShares(t *testing.T) {

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
func TestSecret(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)

	if !secret.Equal(testPoly.Secret()) {
	   t.Error("The secret is expected to be the same one given to it.")
	 }
}

// Verify that the equal function returns true for two polynomials that are
// the same
func TestEqual_Same(t *testing.T) {

	testPoly := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPolyCopy := testPoly
	
	if !testPoly.Equal(testPolyCopy) {
	   t.Error("Polynomials are expected to be equal.")
	 }
}

// Verify that the equal function returns false for two polynomials that are
// diffferent
func TestEqual_Different(t *testing.T) {

	testPoly1 := new(PriPoly).Pick(group, k, secret, random.Stream)
	testPoly2 := new(PriPoly).Pick(group, k, secret, random.Stream)
	
	if testPoly1.Equal(testPoly2) {
	   t.Error("Polynomials are expected to be different.")
	 }
}

// Verify that the equal function panics if the polynomials
// are of different degrees.
func TestEqual_Error1(t *testing.T) {

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

	t.FailNow()
}

// Verify that the equal function panics if the polynomials
// are of different groups.
func TestEqual_Error2(t *testing.T) {

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

	t.FailNow()
}
