package poly

import (
	"fmt"
	"github.com/dedis/crypto/config"
)

// This package provides  a dealer-less distributed verifiable secret sharing using Pedersen VSS scheme
// as explained in "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates"
// This file is only responsible for the setup of a shared secret among n peers.
// The output is a global public polynomial (pubPoly) and a secret share for each peers.

// SharingInfo describe the information needed to construct (and verify) a matrixShare
type SharingInfo struct {
	// How many peer do we need to reconstruct a secret
	K int
	// How many peers do we need to verify
	R int
	// How many peers are collaborating into constructing the shared secret ( i.e. PeerMatrix is of size NxN)
	N int
}

// PeerInfo describe the promise of the others peers with their respective 'promise' struct,
// so that when peer i receives a PeerPromise from peer j, peer i can compute PUBj (i)
// Peer i can also recover information (with others peers) if peer j is disqualified or not responding
type PeerInfo struct {
	// PublicKey is the public key of peer j
	Public abstract.Point

	// Index is the index of peer i in the polynomial (~promise) of peer j
	// It is needed to construct PUBj(i) and to construct the shared secret
	// THis is information is normally sent by peer j to peer i
	Index int

	// Promise is the promise of peer j
	Promise *promise.Promise

	// State related to peer j 's promise
	State *promise.State
}

// PeerMatrix provides method for constructing a matrix of n peers exchanging their promise to produce a global shared secret
type PeerMatrix struct {

	// info is just the info about the polynomials we're gonna use
	info SharingInfo

	// NodeKey is the public / private key pair of the node. It is its base / long-term key pair
	NodeKey *config.KeyPair

	// Promise is the 'promise' used by this peer that will distribute its share amongst the n peers
	Promise *promise.Promise

	// State is the state related to the peer promise
	State *promise.State

	// Peers is an array describing the information that peer i has about every peer j
	// These info would have to be coming from the network (or chan or stg else) from peer j
	Peers []*PeerInfo
}

// init a new PeerMatrix structure
func NewPeerMatrix(sinfo SharingInfo, nodeKey, promiserKey config.KeyPair, peersPublicKey []abstract.Point) *PeerMatrix {

	pm := &PeerMatrix{
		info:    sinfo,
		NodeKey: nodeKey,
		Peers:   make([]*PeerInfo, 0, sinfo.N),
	}
	// put the public key into their peerinfo
	for i, pk := range peersPublicKey {
		pm.Peers[i] = &PeerInfo{
			Public: pk,
		}
	}
	return pm
}
