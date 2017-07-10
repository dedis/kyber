package cosi

import (
	"fmt"
	"testing"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/config"
	"github.com/dedis/kyber/ed25519"
)

var testSuite = ed25519.NewAES128SHA256Ed25519(false)

// TestCoSiCommitment test if the commitment generation is correct
func TestCoSiCommitment(t *testing.T) {
	var length = 5
	cosigner, _ := genCoSigner(length, 0)
	// gen commitments from children
	commitments := genCommitments(cosigner[1:])
	root := cosigner[0]
	root.Commit(nil, commitments)
	// compute the aggregate commitment ourself...
	aggCommit := testSuite.Point().Null()
	// add commitment of children
	for _, com := range commitments {
		aggCommit = aggCommit.Add(aggCommit, com)
	}
	// add commitment of root
	aggCommit = aggCommit.Add(aggCommit, root.commitment)
	if !aggCommit.Equal(root.aggregateCommitment) {
		t.Fatal("Aggregate Commitment are not equal")
	}
}

func TestCoSiChallenge(t *testing.T) {
	cosigner, _ := genCoSigner(5, 0)
	genPostCommitmentPhaseCoSi(cosigner)
	root, children := cosigner[0], cosigner[1:]
	msg := []byte("Hello World CoSi\n")
	chal, err := root.CreateChallenge(msg)
	if err != nil {
		t.Fatal("Error during challenge generation")
	}
	for _, child := range children {
		child.Challenge(chal)
		if !child.challenge.Equal(chal) {
			t.Fatal("Error during challenge on children")
		}
	}
}

// TestCoSiResponse will test wether the response generation is correct or not
func TestCoSiResponse(t *testing.T) {
	msg := []byte("Hello World CoSi")
	// go to the challenge phase
	cosigner, _ := genCoSigner(5, 0)
	genPostChallengePhaseCoSi(cosigner, msg)
	root, children := cosigner[0], cosigner[1:]
	var responses []abstract.Scalar

	// for verification later
	aggResponse := testSuite.Scalar().Zero()
	for _, ch := range children {
		// generate the response of each children
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
		t.Fatal("Responses aggregated not equal")
	}
}

//func TestMask(t *testing.T) {
//
//	n := 5
//	cosigner, _ := genCoSigner(n, 0)
//	//fmt.Printf("%x\n", cosigner[0].mask.bytes())
//	//fmt.Printf("%x\n", cosigner[1].mask.bytes())
//	//fmt.Printf("%x\n", cosigner[2].mask.bytes())
//	//fmt.Printf("%x\n", cosigner[3].mask.bytes())
//	//fmt.Printf("%x\n", cosigner[4].mask.bytes())
//
//	fmt.Printf("%v\n", cosigner[0].mask.MaskBit(0))
//	cosigner[0].mask.SetMaskBit(0, false)
//	fmt.Printf("%v\n", cosigner[0].mask.MaskBit(0))
//	cosigner[0].mask.SetMaskBit(0, true)
//	fmt.Printf("%v\n", cosigner[0].mask.MaskBit(0))
//	fmt.Printf("%x\n", cosigner[0].Bytes())
//	//fmt.Printf("%v\n", cosigner[1].mask.MaskBit(0))
//	//fmt.Printf("%v\n", cosigner[2].mask.MaskBit(0))
//	//fmt.Printf("%v\n", cosigner[3].mask.MaskBit(0))
//	//fmt.Printf("%v\n", cosigner[4].mask.MaskBit(0))
//
//}

func TestCoSigning(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, publics := genCoSigner(3, 0)
	genFinalCoSi(cosigner, msg)
	sig := cosigner[0].Signature()
	if err := VerifySignature(testSuite, publics, msg, sig); err != nil {
		t.Fatal("Error verifying co-signature:", err)
	}

	//var Ed25519Publics []xEd25519.PublicKey
	//for _, p := range publics {
	//	buff, err := p.MarshalBinary()
	//	assert.Nil(t, err)
	//	Ed25519Publics = append(Ed25519Publics, xEd25519.PublicKey(buff))
	//}

	//if !cosi.Verify(Ed25519Publics, nil, msg, sig) {
	//	t.Error("Error verifying co-signature against github.com/bford/golang-x-crypto/ed25519/cosi")
	//}

}

func TestCoSigningMaskHW(t *testing.T) {
	n := 8
	for f := 0; f < n; f++ {
		cosigner, _ := genCoSigner(n, f)
		if cosigner[0].MaskHW() != n-f {
			t.Fatal("Mismatch in number of cosigners: %v vs %v", cosigner[0].MaskHW(), n-f)
		}

	}
}

func TestCoSigningWithFailures(t *testing.T) {
	msg := []byte("Hello World CoSi")
	cosigner, publics := genCoSigner(5, 2)
	genFinalCoSi(cosigner, msg)
	sig := cosigner[0].Signature()
	if err := VerifySignature(testSuite, publics, msg, sig); err != nil {
		t.Fatal("Error verifying co-signature:", err)
	}

	//	var Ed25519Publics []xEd25519.PublicKey
	//	for _, p := range publics {
	//		buff, err := p.MarshalBinary()
	//		assert.Nil(t, err)
	//		Ed25519Publics = append(Ed25519Publics, xEd25519.PublicKey(buff))
	//	}
	//
	//	//if !cosi.Verify(Ed25519Publics, cosi.ThresholdPolicy(3), msg, sig) {
	//	//	t.Error("github.com/bford/golang-x-crypto/ed25519/cosi fork can't verify")
	//	//}
	//	//if cosi.Verify(Ed25519Publics, cosi.ThresholdPolicy(4), msg, sig) {
	//	//	t.Error("github.com/bford/golang-x-crypto/ed25519/cosi fork can't verify")
	//	//}

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

// genPostCommitmentPhaseCoSi returns the Root and its Children CoSi. They have
// already made the Commitment phase.
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
		return fmt.Errorf("Response phase failed:%v", err)
	}
	return nil
}
