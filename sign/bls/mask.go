package bls

import (
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

// Mask is a bitmask of the participation to a collective signature
type Mask struct {
	mask    []byte
	publics []kyber.Point
}

// NewMask creates a new mask from a list of public keys. If a key is provided, it
// will set the bit of the key to 1 or return an error if it is not found
func NewMask(suite pairing.Suite, publics []kyber.Point, myKey kyber.Point) (*Mask, error) {
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.Len())

	if myKey != nil {
		for i, key := range publics {
			if key.Equal(myKey) {
				m.SetBit(i, true)
				return m, nil
			}
		}

		return nil, errors.New("key not found")
	}

	return m, nil
}

// Mask returns the bitmask as a byte array
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone[:], m.mask)
	return clone
}

// Len returns the length of the byte array necessary to store the bitmask
func (m *Mask) Len() int {
	return (len(m.publics) + 7) / 8
}

// SetMask replaces the current mask by the new one if the length matches
func (m *Mask) SetMask(mask []byte) error {
	if m.Len() != len(mask) {
		return fmt.Errorf("mismatching mask lengths")
	}

	m.mask = mask
	return nil
}

// SetBit turns on or off the bit at the given index
func (m *Mask) SetBit(i int, enable bool) error {
	if i >= len(m.publics) || i < 0 {
		return errors.New("index out of range")
	}

	byteIndex := i / 8
	mask := byte(1) << uint(i&7)
	if enable {
		m.mask[byteIndex] ^= mask
	} else {
		m.mask[byteIndex] ^= mask
	}
	return nil
}

// Participants returns the list of public keys participating
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
