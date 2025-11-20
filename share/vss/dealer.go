package vss

import (
	"errors"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/protobuf"
)

// Dealer encapsulates for creating and distributing the shares and for
// replying to any Responses.
type Dealer struct {
	suite Suite
	// long is the longterm key of the Dealer
	long          kyber.Scalar
	pub           kyber.Point
	secret        kyber.Scalar
	secretCommits []kyber.Point
	verifiers     []kyber.Point
	hkdfContext   []byte
	// threshold of shares that is needed to reconstruct the secret
	t int
	// sessionID is a unique identifier for the whole session of the scheme
	sessionID []byte
	// list of deals this Dealer has generated
	deals []*Deal
	Aggregator
}

func NewDealer(suite Suite, long, secret kyber.Scalar, pub kyber.Point,
	secretCommits, verifiers []kyber.Point, hkdfContext []byte,
	t int, sessionID []byte, deals []*Deal, aggregator Aggregator) *Dealer {
	return &Dealer{
		suite:         suite,
		long:          long,
		pub:           pub,
		secret:        secret,
		secretCommits: secretCommits,
		verifiers:     verifiers,
		hkdfContext:   hkdfContext,
		t:             t,
		sessionID:     sessionID,
		deals:         deals,
		Aggregator:    aggregator,
	}
}

func (d *Dealer) Deals() []*Deal {
	return d.deals
}

func (d *Dealer) Threshold() int {
	return d.t
}

// PlaintextDeal returns the plaintext version of the deal destined for peer i.
// Use this only for testing.
func (d *Dealer) PlaintextDeal(i int) (*Deal, error) {
	if i >= len(d.deals) {
		return nil, errors.New("dealer: PlaintextDeal given wrong index")
	}
	return d.deals[i], nil
}

// EncryptedDeal returns the encryption of the deal that must be given to the
// verifier at index i.
// The dealer first generates a temporary Diffie Hellman key, signs it using its
// longterm key, and computes the shared key depending on its longterm and
// ephemeral key and the verifier's public key.
// This shared key is then fed into a HKDF whose output is the key to a AEAD
// (AES256-GCM) scheme to encrypt the deal.
func (d *Dealer) EncryptedDeal(i int) (*EncryptedDeal, error) {
	vPub, ok := FindPub(d.verifiers, uint32(i))
	if !ok {
		return nil, errors.New("dealer: wrong index to generate encrypted deal")
	}
	// gen ephemeral key
	dhSecret := d.suite.Scalar().Pick(d.suite.RandomStream())
	dhPublic := d.suite.Point().Mul(dhSecret, nil)
	// signs the public key
	dhPublicBuff, _ := dhPublic.MarshalBinary()
	signature, err := schnorr.Sign(d.suite, d.long, dhPublicBuff)
	if err != nil {
		return nil, err
	}
	// AES128-GCM
	pre := DhExchange(d.suite, dhSecret, vPub)
	gcm, err := NewAEAD(d.suite.Hash, pre, d.hkdfContext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	dealBuff, err := protobuf.Encode(d.deals[i])
	if err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nil, nonce, dealBuff, d.hkdfContext)
	return &EncryptedDeal{
		DHKey:     dhPublic,
		Signature: signature,
		Cipher:    encrypted,
	}, nil
}

// EncryptedDeals calls `EncryptedDeal` for each index of the verifier and
// returns the list of encrypted deals. Each index in the returned slice
// corresponds to the index in the list of verifiers.
func (d *Dealer) EncryptedDeals() ([]*EncryptedDeal, error) {
	deals := make([]*EncryptedDeal, len(d.verifiers))
	var err error
	for i := range d.verifiers {
		deals[i], err = d.EncryptedDeal(i)
		if err != nil {
			return nil, err
		}
	}
	return deals, nil
}

// ProcessResponse analyzes the given Response. If it's a valid complaint, then
// it returns a Justification. This Justification must be broadcast to every
// participant. If it's an invalid complaint, it returns an error about the
// complaint. The verifiers will also ignore an invalid Complaint.
func (d *Dealer) ProcessResponse(r *Response) (*Justification, error) {
	if err := d.VerifyResponse(r); err != nil {
		return nil, err
	}
	if r.StatusApproved {
		//nolint:nilnil // Expected behavior
		return nil, nil
	}

	j := &Justification{
		SessionID: d.sessionID,
		// index is guaranteed to be good because of d.VerifyResponse before
		Index: r.Index,
		Deal:  d.deals[int(r.Index)],
	}

	msg, err := j.Hash(d.suite)
	if err != nil {
		return nil, err
	}

	sig, err := schnorr.Sign(d.suite, d.long, msg)
	if err != nil {
		return nil, err
	}
	j.Signature = sig
	return j, nil
}

// SecretCommit returns the commitment of the secret being shared by this
// dealer. This function is only to be called once the deal has enough approvals
// and is verified otherwise it returns nil.
func (d *Dealer) SecretCommit() kyber.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.suite.Point().Mul(d.secret, nil)
}

// Commits returns the commitments of the coefficient of the secret polynomial
// the Dealer is sharing.
func (d *Dealer) Commits() []kyber.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.secretCommits
}

// Key returns the longterm key pair used by this Dealer.
func (d *Dealer) Key() (secret kyber.Scalar, public kyber.Point) {
	return d.long, d.pub
}

// SessionID returns the current sessionID generated by this dealer for this
// protocol run.
func (d *Dealer) SessionID() []byte {
	return d.sessionID
}
