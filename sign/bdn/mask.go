package bdn

import (
	"errors"
	"fmt"
	"slices"

	"go.dedis.ch/kyber/v4"
)

// Mask is a bitmask of the participation to a collective signature.
type Mask struct {
	// The bitmask indicating which public keys are enabled/disabled for aggregation. This is
	// the only mutable field.
	mask []byte

	// The following fields are immutable and should not be changed after the mask is created.
	// They may be shared between multiple masks.

	// Public keys for aggregation & signature verification.
	publics []kyber.Point
	// Coefficients used when aggregating signatures.
	publicCoefs []kyber.Scalar
	// Terms used to aggregate public keys
	publicTerms []kyber.Point
}

// NewMask creates a new mask from a list of public keys. If a key is provided, it
// will set the bit of the key to 1 or return an error if it is not found.
//
// The returned Mask will contain pre-computed terms and coefficients for all provided public
// keys, so it should be re-used for optimal performance (e.g., by creating a "base" mask and
// cloning it whenever aggregating signatures and/or public keys).
func NewMask(group kyber.Group, publics []kyber.Point, myKey kyber.Point) (*Mask, error) {
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.Len())

	if myKey != nil {
		for i, key := range publics {
			if key.Equal(myKey) {
				err := m.SetBit(i, true)
				return m, err
			}
		}

		return nil, errors.New("key not found")
	}

	var err error
	m.publicCoefs, err = hashPointToR(group, publics)
	if err != nil {
		return nil, fmt.Errorf("failed to hash public keys: %w", err)
	}

	m.publicTerms = make([]kyber.Point, len(publics))
	for i, pub := range publics {
		pubC := pub.Clone().Mul(m.publicCoefs[i], pub)
		m.publicTerms[i] = pubC.Add(pubC, pub)
	}

	return m, nil
}

// Mask returns the bitmask as a byte array.
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone, m.mask)
	return clone
}

// Len returns the length of the byte array necessary to store the bitmask.
func (m *Mask) Len() int {
	return (len(m.publics) + 7) / 8
}

// SetMask replaces the current mask by the new one if the length matches.
func (m *Mask) SetMask(mask []byte) error {
	if m.Len() != len(mask) {
		return fmt.Errorf("mismatching mask lengths")
	}

	m.mask = mask
	return nil
}

// GetBit returns true if the given bit is set.
func (m *Mask) GetBit(i int) (bool, error) {
	if i >= len(m.publics) || i < 0 {
		return false, errors.New("index out of range")
	}

	byteIndex := i / 8
	mask := byte(1) << uint(i&7)
	return m.mask[byteIndex]&mask != 0, nil
}

// SetBit turns on or off the bit at the given index.
func (m *Mask) SetBit(i int, enable bool) error {
	if i >= len(m.publics) || i < 0 {
		return errors.New("index out of range")
	}

	byteIndex := i / 8
	mask := byte(1) << uint(i&7)
	if enable {
		m.mask[byteIndex] |= mask
	} else {
		m.mask[byteIndex] &^= mask
	}
	return nil
}

// forEachBitEnabled is a helper to iterate over the bits set to 1 in the mask
// and to return the result of the callback only if it is positive.
func (m *Mask) forEachBitEnabled(f func(i, j, n int) int) int {
	n := 0
	for i, b := range m.mask {
		for j := uint(0); j < 8; j++ {
			mm := byte(1) << (j & 7)

			if b&mm != 0 {
				if res := f(i, int(j), n); res >= 0 {
					return res
				}

				n++
			}
		}
	}

	return -1
}

// IndexOfNthEnabled returns the index of the nth enabled bit or -1 if out of bounds.
func (m *Mask) IndexOfNthEnabled(nth int) int {
	return m.forEachBitEnabled(func(i, j, n int) int {
		if n == nth {
			return i*8 + int(j)
		}

		return -1
	})
}

// NthEnabledAtIndex returns the sum of bits set to 1 until the given index. In other
// words, it returns how many bits are enabled before the given index.
func (m *Mask) NthEnabledAtIndex(idx int) int {
	return m.forEachBitEnabled(func(i, j, n int) int {
		if i*8+int(j) == idx {
			return n
		}

		return -1
	})
}

// Publics returns a copy of the list of public keys.
func (m *Mask) Publics() []kyber.Point {
	pubs := make([]kyber.Point, len(m.publics))
	copy(pubs, m.publics)
	return pubs
}

// Participants returns the list of public keys participating.
func (m *Mask) Participants() []kyber.Point {
	pp := []kyber.Point{}
	for i, p := range m.publics {
		byteIndex := i / 8
		mask := byte(1) << uint(i&7)
		if (m.mask[byteIndex] & mask) != 0 {
			pp = append(pp, p)
		}
	}

	return pp
}

// CountEnabled returns the number of bit set to 1
func (m *Mask) CountEnabled() int {
	count := 0
	for i := range m.publics {
		byteIndex := i / 8
		mask := byte(1) << uint(i&7)
		if (m.mask[byteIndex] & mask) != 0 {
			count++
		}
	}
	return count
}

// CountTotal returns the number of potential participants
func (m *Mask) CountTotal() int {
	return len(m.publics)
}

// Merge merges the given mask to the current one only if
// the length matches
func (m *Mask) Merge(mask []byte) error {
	if len(m.mask) != len(mask) {
		return errors.New("mismatching mask length")
	}

	for i := range m.mask {
		m.mask[i] |= mask[i]
	}

	return nil
}

// Clone copies the mask while keeping the precomputed coefficients, etc. This method is thread safe
// and does not modify the original mask. Modifications to the new Mask will not affect the original.
func (m *Mask) Clone() *Mask {
	return &Mask{
		mask:        slices.Clone(m.mask),
		publics:     m.publics,
		publicCoefs: m.publicCoefs,
		publicTerms: m.publicTerms,
	}
}
