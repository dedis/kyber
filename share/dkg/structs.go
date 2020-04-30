package dkg

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
)

type Index = uint32

type Node struct {
	Index  Index
	Public kyber.Point
}

func (n *Node) Equal(n2 *Node) bool {
	return n.Index == n2.Index && n.Public.Equal(n2.Public)
}

type Result struct {
	QUAL []Node
	Key  *DistKeyShare
}

func (r *Result) PublicEqual(r2 *Result) bool {
	if len(r.Key.Commits) != len(r2.Key.Commits) {
		return false
	}
	if len(r.QUAL) != len(r2.QUAL) {
		return false
	}
	lenC := len(r.Key.Commits)
	for i := 0; i < lenC; i++ {
		if !r.Key.Commits[i].Equal(r2.Key.Commits[i]) {
			return false
		}
	}
	for i := 0; i < len(r.QUAL); i++ {
		if !r.QUAL[i].Equal(&r2.QUAL[i]) {
			return false
		}
	}
	return true
}

// DistKeyShare holds the share of a distributed key for a participant.
type DistKeyShare struct {
	// Coefficients of the public polynomial holding the public key.
	Commits []kyber.Point
	// Share of the distributed secret which is private information.
	Share *share.PriShare
}

// Public returns the public key associated with the distributed private key.
func (d *DistKeyShare) Public() kyber.Point {
	return d.Commits[0]
}

// PriShare implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) PriShare() *share.PriShare {
	return d.Share
}

// Commitments implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) Commitments() []kyber.Point {
	return d.Commits
}

// Deal holds the Deal for one participant as well as the index of the issuing
// Dealer.
type Deal struct {
	// Index of the share holder
	ShareIndex uint32
	// encrypted share issued to the share holder
	EncryptedShare []byte
}

type DealBundle struct {
	DealerIndex uint32
	Deals       []Deal
	// Public coefficients of the public polynomial used to create the shares
	Public []kyber.Point
}

// Hash hashes the index, public coefficients and deals
func (d *DealBundle) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, d.DealerIndex)
	for _, c := range d.Public {
		cbuff, _ := c.MarshalBinary()
		h.Write(cbuff)
	}
	for _, deal := range d.Deals {
		binary.Write(h, binary.BigEndian, deal.ShareIndex)
		h.Write(deal.EncryptedShare)
	}
	return h.Sum(nil)
}

// Response holds the Response from another participant as well as the index of
// the target Dealer.
type Response struct {
	// Index of the Dealer for which this response is for
	DealerIndex uint32
	Status      bool
}

type ResponseBundle struct {
	// Index of the share holder for which these reponses are for
	ShareIndex uint32
	Responses  []Response
}

// Hash hashes the share index and responses
func (r *ResponseBundle) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, r.ShareIndex)
	for _, resp := range r.Responses {
		binary.Write(h, binary.BigEndian, resp.DealerIndex)
		if resp.Status {
			binary.Write(h, binary.BigEndian, byte(1))
		} else {
			binary.Write(h, binary.BigEndian, byte(0))
		}
	}
	return h.Sum(nil)
}

type JustificationBundle struct {
	DealerIndex    uint32
	Justifications []Justification
}

type Justification struct {
	ShareIndex uint32
	Share      kyber.Scalar
}

func (j *JustificationBundle) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, j.DealerIndex)
	for _, just := range j.Justifications {
		binary.Write(h, binary.BigEndian, just.ShareIndex)
		sbuff, _ := just.Share.MarshalBinary()
		h.Write(sbuff)
	}
	return h.Sum(nil)
}

type AuthDealBundle struct {
	Bundle    *DealBundle
	Signature []byte
}

type AuthResponseBundle struct {
	Bundle    *ResponseBundle
	Signature []byte
}

type AuthJustifBundle struct {
	Bundle    *JustificationBundle
	Signature []byte
}
