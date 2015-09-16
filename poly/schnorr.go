package poly

import (
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
)

// This file describe the Distributed Threshold Schnorr Signature

// Schnorr will holds the data necessary to complete a distributed schnorr signature
// And will implement methods to do so
// Basically you can setup a schnorr struct with a LongTerm shared secret
// When you want to sign something, you
//  - Start a new round specifying the random shared secret chosen and the message to sign
//  - Generate the partial signature of the current node
//  - Collect every others partial signature
//  - Generate signature
//  - ... Do what ever you want to do with
//  - You can now start again a new round with the same schnorr struct
// When you want to verify a given signature :
//  - You can just call from the schnorr struct : schnorr.VerifySignature(SchnorrSig, msg)
// CAREFUL: your schnorr signature is a LONG TERM signature, you must keep the same throughout the differents rounds
// otherwise you won't be able to verify any signatures. To be more precise, you just have to keep the same LongTerm sharedSecret
// and PolyInfo. If you know these are the same throughout differents rounds, you can create many schnorr structs. This is
// definitly NOT the way it is intented to be used, so use it at your own risks.
type Schnorr struct {

	// The info describing which kind of polynomials we using, on which groups etc
	info PolyInfo

	// The long-term shared secret evaluated by receivers
	Longterm *SharedSecret

	////////////////////////////////////////////////////
	// FOR A GIVEN ROUND, we have the following members :

	// hash is the hash of the message
	hash *abstract.Secret

	// The short term shared secret to use for this signature ONLY /!\
	// i.e. the random secret in the regular schnorr signature
	random *SharedSecret

	// The partials signature of each other peers (i.e. receiver)
	partials []*PartialSchnorrSig

	/////////////////////////////////////////////////////
}

// Partial Schnorr Sig represents the partial signatures that each peers must generate in order to
// generate the "global" signature. This struct must be sent across each peers for each peers
type PartialSchnorrSig struct {
	// The index of this partial signature regarding the global one
	// same as the "receiver" index in the joint.go code
	Index int

	// The partial signature itself
	Part *abstract.Secret
}

// SchnorrSig represents the final signature of a distribtued threshold schnorr signature
// which can be verified against a message
// This struct is not intended to be constructed manually but can be:
//  - produce by the Schnorr struct
//  - verified against a Schnorr struct
type SchnorrSig struct {

	// the signature itself
	signature *abstract.Secret

	// the random public polynomial used during the signature generation
	random *PubPoly
}

// NewSchnorr nstantiate a Schnorr  struct . A wrapper around Init
func NewSchnorr(info PolyInfo, longterm *SharedSecret) *Schnorr {
	return new(Schnorr).Init(info, longterm)
}

// Init initialize the Schnorr struct
func (s *Schnorr) Init(info PolyInfo, longterm *SharedSecret) *Schnorr {
	s.info = info
	s.Longterm = longterm
	return s
}

// NewRound set the random key for the d.schnorr algo + set the msg to be signed
// You call this function when you want a new signature to be issued on a specific message
// The security of the d. schnorr signature protocol is the same as the regular :
// The random secret MUST BE FRESH for EACH signature / signed message (hence the 'NewRound')
func (s *Schnorr) NewRound(random *SharedSecret, msg []byte) error {
	s.random = random
	s.hash = nil
	s.partials = nil // erase the previous partil signature from previous round
	s.partials = make([]*PartialSchnorrSig, s.info.N)
	hash, err := s.hashMessage(msg, s.random.Pub.SecretCommit())
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to hash the message with the given shared secret : %v", err))
	}
	s.hash = &hash
	return nil
}

// hash returns a hash of the message and the random secret
// H( m || V )
// Returns an error if something went wrong with the marshalling
func (s *Schnorr) hashMessage(msg []byte, v abstract.Point) (abstract.Secret, error) {
	vb, err := v.MarshalBinary()
	if err != nil {
		return nil, err
	}
	c := s.info.Suite.Cipher(vb)
	c.Message(nil, nil, msg)
	return s.info.Suite.Secret().Pick(c), nil
}

// Verify if the received structures are good
// tests the partials shares if there is some
func (s *Schnorr) verify() error {
	if s.Longterm.Index != s.random.Index {
		return errors.New("The index for the longterm shared secret and the random secret differs for this peer.")
	}
	nsig := 0
	for i, _ := range s.partials {
		if s.partials[i] != nil {
			nsig += 1
		}
	}
	if nsig < s.info.T {
		return errors.New(fmt.Sprintf("Received to few Partial Signatures (%d vs %d) to complete a global schnorr signature", len(s.partials), s.info.T))
	}
	return nil
}

// verifyPartialSig will verify if a given partial signature can be checked against the longterm and random secrets
// of the schnorr structures.
func (s *Schnorr) verifyPartialSig(ps *PartialSchnorrSig) error {
	// compute left part of the equation
	left := s.info.Suite.Point().Mul(s.info.Suite.Point().Base(), *ps.Part)
	// compute right part of the equation
	right := s.info.Suite.Point().Add(s.random.Pub.Eval(ps.Index), s.info.Suite.Point().Mul(s.Longterm.Pub.Eval(ps.Index), *s.hash))
	if !left.Equal(right) {
		return errors.New(fmt.Sprintf("Partial Signature of peer %d could not be validated.", ps.Index))
	}
	return nil
}

// index returns the index of the peer holding this schnorr struct
// the index of its share in the polynomials used
func (s *Schnorr) index() int {
	return s.Longterm.Index
}

// RevealPartialSig reveals the partial signature for this peer
// Si = Ri + H(m || V) * Pi
// with :
// 	- Ri = share of the random secret for peer i
//  - V  = public commitment of the random secret (i.e. Public random poly evaluated at point 0 )
//  - Pi = share of the longterm secret for peer i
// This signature is to be sent to each others peers
func (s *Schnorr) RevealPartialSig() *PartialSchnorrSig {
	hash := *s.hash
	sigma := s.info.Suite.Secret().Zero()
	sigma = sigma.Add(sigma, *s.random.Share)
	// H(m||v) * Pi
	hash = s.info.Suite.Secret().Mul(hash, *s.Longterm.Share)
	// Ri + H(m||V) * Pi
	sigma = sigma.Add(sigma, hash)

	psc := &PartialSchnorrSig{
		Index: s.index(),
		Part:  &sigma,
	}
	return psc
}

// AddPartialSig receives a signature from others peer,
// adds it to its list of partial signatures and verify it
// It return an error if
// - 	it can not validate this given partial signature
// 		against the longterm and random shared secret
// - there is already an partial signature added for this index
// NOTE : let s = RevealPartialSig(), s is NOT added automatically to the
// set of partial signature, for now you have to do it yourself by calling
// AddPartialSig(s)
func (s *Schnorr) AddPartialSig(ps *PartialSchnorrSig) error {
	if ps.Index >= s.info.N {
		return errors.New(fmt.Sprintf("Cannot add signature with index %d whereas schnorr could have max %s partial signatures", ps.Index, s.info.N))
	}
	if s.partials[ps.Index] != nil {
		return errors.New(fmt.Sprintf("A Partial Signature has already been added for this index %d", ps.Index))
	}
	if err := s.verifyPartialSig(ps); err != nil {
		return errors.New(fmt.Sprintf("Partial signature to add is not valid : %v", err))
	}
	s.partials[ps.Index] = ps
	return nil
}

// SchnorrSig  will generate the global schnorr signature
// By reconstructing the secret that the partial responses contains
func (s *Schnorr) SchnorrSig() (*SchnorrSig, error) {
	// automatic verification
	// TODO : change this into a bool flag or public method ?
	if err := s.verify(); err != nil {
		return nil, err
	}

	pri := PriShares{}
	pri.Empty(s.info.Suite, s.info.T, s.info.N)
	for i, ps := range s.partials {
		pri.SetShare(ps.Index, *s.partials[i].Part)
	}
	// lagrange interpolation to compute the gamma
	gamma := pri.Secret()
	sig := &SchnorrSig{
		random:    s.random.Pub,
		signature: &gamma,
	}
	return sig, nil
}

// VerifySchnorrSig will verify if a given signature is correct regarding the message
// NOTE: This belongs to the schnorr structs however it can be called at any time you want
// This check is static, meaning it only needs the longterm shared secret, and the signature to
// check. Think of the schnorr signature as a black box having two inputs
//  - a message to be signed + a random secret ==> NewRound
//  - a message + a signature to check on ==> VerifySchnorrSig
func (s *Schnorr) VerifySchnorrSig(sig *SchnorrSig, msg []byte) error {
	// gamma * G
	left := s.info.Suite.Point().Mul(s.info.Suite.Point().Base(), *sig.signature)

	randomCommit := sig.random.SecretCommit()
	publicCommit := s.Longterm.Pub.SecretCommit()
	hash, err := s.hashMessage(msg, randomCommit)

	if err != nil {
		return err
	}
	// RandomSecretCOmmit + H( ...) * LongtermSecretCommit
	right := s.info.Suite.Point().Add(randomCommit, s.info.Suite.Point().Mul(publicCommit, hash))

	if !left.Equal(right) {
		return errors.New("Signature could not have been verified against the message")
	}
	return nil
}
