package bdn

import (
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/sign"
)

//nolint:interfacebloat
type Mask interface {
	GetBit(i int) (bool, error)
	SetBit(i int, enable bool) error

	IndexOfNthEnabled(nth int) int
	NthEnabledAtIndex(idx int) int

	Publics() []kyber.Point
	Participants() []kyber.Point

	CountEnabled() int
	CountTotal() int

	Len() int
	Mask() []byte
	SetMask(mask []byte) error
	Merge(mask []byte) error
}

var _ Mask = (*sign.Mask)(nil)

// We need to rename this, otherwise we have a public field named Mask (when we embed it) which
// conflicts with the function named Mask. It also makes it private, which is nice.
type maskI = Mask

type CachedMask struct {
	maskI
	coefs   []kyber.Scalar
	pubKeyC []kyber.Point
	// We could call Mask.Publics() instead of keeping these here, but that function copies the
	// slice and this field lets us avoid that copy.
	publics []kyber.Point
}

// Convert the passed mask (likely a *sign.Mask) into a BDN-specific mask with pre-computed terms.
//
// This cached mask will:
//
//  1. Pre-compute coefficients for signature aggregation. Once the CachedMask has been instantiated,
//     distinct sets of signatures can be aggregated without any BLAKE2S hashing.
//  2. Pre-computes the terms for public key aggregation. Once the CachedMask has been instantiated,
//     distinct sets of public keys can be aggregated by simply summing the cached terms, ~2 orders
//     of magnitude faster than aggregating from scratch.
func NewCachedMask(mask Mask) (*CachedMask, error) {
	return newCachedMask(mask, true)
}

func newCachedMask(mask Mask, precomputePubC bool) (*CachedMask, error) {
	if m, ok := mask.(*CachedMask); ok {
		return m, nil
	}

	publics := mask.Publics()
	coefs, err := hashPointToR(publics)
	if err != nil {
		return nil, fmt.Errorf("failed to hash public keys: %w", err)
	}

	cm := &CachedMask{
		maskI:   mask,
		coefs:   coefs,
		publics: publics,
	}

	if precomputePubC {
		pubKeyC := make([]kyber.Point, len(publics))
		for i := range publics {
			pubKeyC[i] = cm.getOrComputePubC(i)
		}
		cm.pubKeyC = pubKeyC
	}

	return cm, err
}

// Clone copies the BDN mask while keeping the precomputed coefficients, etc.
func (cm *CachedMask) Clone() *CachedMask {
	newMask, err := sign.NewMask(cm.publics, nil)
	if err != nil {
		// Not possible given that we didn't pass our own key.
		panic(fmt.Sprintf("failed to create mask: %s", err))
	}
	if err := newMask.SetMask(cm.Mask()); err != nil {
		// Not possible given that we're using the same sized mask.
		panic(fmt.Sprintf("failed to create mask: %s", err))
	}
	return &CachedMask{
		maskI:   newMask,
		coefs:   cm.coefs,
		pubKeyC: cm.pubKeyC,
		publics: cm.publics,
	}
}

func (cm *CachedMask) getOrComputePubC(i int) kyber.Point {
	if cm.pubKeyC == nil {
		// NOTE: don't cache here as we may be sharing this mask between threads.
		pub := cm.publics[i]
		pubC := pub.Clone().Mul(cm.coefs[i], pub)
		return pubC.Add(pubC, pub)
	}
	return cm.pubKeyC[i]
}
