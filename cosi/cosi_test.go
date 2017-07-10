package cosi

import (
	"fmt"
	"testing"

	xEd25519 "github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/config"
	"github.com/dedis/kyber/ed25519"
	"github.com/stretchr/testify/assert"
)

var testSuite = ed25519.NewAES128SHA256Ed25519(false)

// TestCoSiCommitment tests correctness of commitment generation.
func TestCoSiCommitment(t *testing.T) {
	cosigner, _ := genCoSigner(5, 0)
	// gen commitments from children
	commitments := genCommitments(cosigner[1:])
	root := cosigner[0]
	root.Commit(nil, commitments)
	// compute the aggregate commitment manually
	aggCommit := testSuite.Point().Null()
	// add commitments of children
	for _, com := range commitments {
		aggCommit = aggCommit.Add(aggCommit, com)
	}
	// add commitment of root
	aggCommit = aggCommit.Add(aggCommit, root.commitment)
	if !aggCommit.Equal(root.aggregateCommitment) {
		t.Fatal("Aggregate commitments are not equal")
	}
}

// TestCoSiChallenge tests correctness of challenge generation.
func TestCoSiChallenge(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, _ := genCoSigner(5, 0)
	genPostCommitmentPhaseCoSi(cosigner)
	root, children := cosigner[0], cosigner[1:]
	chal, err := root.CreateChallenge(msg)
	if err != nil {
		t.Fatal("Error creating challenge:", err)
	}
	for _, child := range children {
		child.Challenge(chal)
		if !child.challenge.Equal(chal) {
			t.Fatal("Error creating challenge at children")
		}
	}
}

// TestCoSiResponse tests correctness of response generation.
func TestCoSiResponse(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, _ := genCoSigner(5, 0)
	// go to the challenge phase
	genPostChallengePhaseCoSi(cosigner, msg)
	root, children := cosigner[0], cosigner[1:]
	var responses []abstract.Scalar

	aggResponse := testSuite.Scalar().Zero()
	for _, ch := range children {
		// generate response for each children
		r, err := ch.CreateResponse()
		if err != nil {
			t.Fatal("Error creating response:", err)
		}
		responses = append(responses, r)
		aggResponse = aggResponse.Add(aggResponse, r)
	}
	// pass them up to the root
	_, err := root.Response(responses)
	if err != nil {
		t.Fatal("Response phase failed:", err)
	}

	// verify it
	aggResponse = aggResponse.Add(aggResponse, root.response)
	if !aggResponse.Equal(root.aggregateResponse) {
		t.Fatal("Aggregate responses are not equal")
	}
}

func TestCoSigning(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, publics := genCoSigner(3, 0)
	genFinalCoSi(cosigner, msg)
	sig := cosigner[0].Signature()
	if err := VerifySignature(testSuite, publics, msg, sig); err != nil {
		t.Fatal("Error verifying cosignature:", err)
	}

	// flip bits of participation mask to maintain compatibility to Bryan's code
	for i := 64; i < len(sig); i++ {
		sig[i] ^= 0xff
	}

	var Ed25519Publics []xEd25519.PublicKey
	for _, p := range publics {
		buff, err := p.MarshalBinary()
		assert.Nil(t, err)
		Ed25519Publics = append(Ed25519Publics, xEd25519.PublicKey(buff))
	}

	if !cosi.Verify(Ed25519Publics, nil, msg, sig) {
		t.Error("Error verifying cosignature against github.com/bford/golang-x-crypto/ed25519/cosi")
	}

}

func TestCoSigningMaskEnabled(t *testing.T) {
	n := 8
	for f := 0; f < n; f++ {
		cosigner, _ := genCoSigner(n, f)
		if cosigner[0].MaskEnabled() != n-f {
			t.Fatal("Mismatch in number of cosigners: %v vs %v", cosigner[0].MaskEnabled(), n-f)
		}

	}
}

func TestCoSigningWithFailures(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, publics := genCoSigner(5, 2)
	genFinalCoSi(cosigner, msg)
	sig := cosigner[0].Signature()
	if err := VerifySignature(testSuite, publics, msg, sig); err != nil {
		t.Fatal("Error verifying cosignature:", err)
	}

	// flip bits of participation mask to maintain compatibility to Bryan's code
	for i := 64; i < len(sig); i++ {
		sig[i] ^= 0xff
	}

	var Ed25519Publics []xEd25519.PublicKey
	for _, p := range publics {
		buff, err := p.MarshalBinary()
		assert.Nil(t, err)
		Ed25519Publics = append(Ed25519Publics, xEd25519.PublicKey(buff))
	}

	if !cosi.Verify(Ed25519Publics, cosi.ThresholdPolicy(3), msg, sig) {
		t.Error("Error verifying cosignature against github.com/bford/golang-x-crypto/ed25519/cosi")
	}
	if cosi.Verify(Ed25519Publics, cosi.ThresholdPolicy(4), msg, sig) {
		t.Error("Error verifying cosignature against github.com/bford/golang-x-crypto/ed25519/cosi")
	}

}

func genKeyPair(nb int) ([]*config.KeyPair, []abstract.Point) {
	var kps []*config.KeyPair
	var publics []abstract.Point
	for i := 0; i < nb; i++ {
		kp := config.NewKeyPair(testSuite)
		kps = append(kps, kp)
		publics = append(publics, kp.Public)
	}
	return kps, publics
}

func genCoSigner(n int, f int) (cosigner []*CoSi, publics []abstract.Point) {
	kps, publics := genKeyPair(n)
	for i := 0; i < n-f; i++ {
		cosigner = append(cosigner, NewCoSi(testSuite, kps[i].Secret, publics))
	}
	for i := range cosigner {
		for j := n - f; j < n; j++ {
			cosigner[i].SetMaskBit(j, false)
		}
	}
	return
}

func genCommitments(cosigner []*CoSi) []abstract.Point {
	commitments := make([]abstract.Point, len(cosigner))
	for i := range cosigner {
		commitments[i] = cosigner[i].CreateCommitment(nil)
	}
	return commitments
}

func genPostCommitmentPhaseCoSi(cosigner []*CoSi) {
	commitments := genCommitments(cosigner[1:])
	root := cosigner[0]
	root.Commit(nil, commitments)
}

func genPostChallengePhaseCoSi(cosigner []*CoSi, msg []byte) {
	genPostCommitmentPhaseCoSi(cosigner)
	chal, _ := cosigner[0].CreateChallenge(msg)
	for _, ch := range cosigner[1:] {
		ch.Challenge(chal)
	}
}

func genFinalCoSi(cosigner []*CoSi, msg []byte) error {
	genPostChallengePhaseCoSi(cosigner, msg)
	children := cosigner[1:]
	root := cosigner[0]
	// go to the challenge phase
	var responses []abstract.Scalar
	for _, ch := range children {
		resp, err := ch.CreateResponse()
		if err != nil {
			panic("Aie")
		}
		responses = append(responses, resp)
	}
	// pass them up to the root
	_, err := root.Response(responses)
	if err != nil {
		return fmt.Errorf("Response phase failed:", err)
	}
	return nil
}
