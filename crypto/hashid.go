package crypto

import (
	"bytes"
	"errors"
)

// HashID is the Cryptographic hash content-IDs
type HashID []byte

// Bit returns if the given bit is set or not
func (id HashID) Bit(i uint) int {
	return int(id[i>>3] >> (i & 7))
}

// Level finds the skip-chain level of an ID
func (id *HashID) Level() int {
	var level uint
	for id.Bit(level) == 0 {
		level++
	}
	return int(level)
}

// String converts the HashID to a string, convenience for
// map[string] because map[HashID] is not possible.
func (id HashID) String() string {
	return string(id)
}

// ByHashID is for sorting arrays of HashIds
type ByHashID []HashID

// Len returns the length of the byhashid
func (h ByHashID) Len() int { return len(h) }

// Swap takes two hashes and inverts them
func (h ByHashID) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Less checks if the first is less than the second
func (h ByHashID) Less(i, j int) bool { return bytes.Compare(h[i], h[j]) < 0 }

// HashGet is the context for looking up content blobs by self-certifying HashId.
// Implementations can be either local (same-node) or remote (cross-node).
type HashGet interface {

	// Get lookups and returns the binary blob for a given content HashId.
	// Checks and returns an error if the hash doesn't match the content;
	// the caller doesn't need to check this correspondence.
	Get(id HashID) ([]byte, error)
}

// HashMap is a simple local-only, map-based implementation of HashGet interface
type HashMap map[string][]byte

// Put adds an element to the hashmap
func (m HashMap) Put(id HashID, data []byte) {
	m[string(id)] = data
}

// Get returns an element from the hashmap
func (m HashMap) Get(id HashID) ([]byte, error) {
	blob, ok := m[string(id)]
	if !ok {
		return nil, errors.New("HashId not found")
	}
	return blob, nil
}
