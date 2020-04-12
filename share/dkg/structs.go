package dkg

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
)

type Node struct {
	Index  uint32
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
	Public      *share.PubPoly
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

type JustificationBundle struct {
	DealerIndex    uint32
	Justifications []Justification
}

type Justification struct {
	ShareIndex uint32
	Share      kyber.Scalar
}
