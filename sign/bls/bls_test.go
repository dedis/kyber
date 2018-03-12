package bls

import (
	"testing"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
)

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuiteBN256()
	private, public := NewKeyPair(suite, random.New())
	sig := Sign(suite, private, msg)
	if err := Verify(suite, public, msg, sig); err != nil {
		t.Fatal(err)
	}
}
