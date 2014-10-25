package sha3

import (
	"github.com/dedis/crypto/abstract"
)

// NewSponge128 creates a new SHAKE128 sponge cipher.
// Its generic security strength is 128 bits against all attacks if
// input keys are at least 16 bytes and output hashes are at least 32 bytes.
func NewSponge128() abstract.Sponge {
	return abstract.Sponge{&sponge{rate: 168, keyLen: 16, dsbyte: 0x1f}}
}

// NewSponge256 creates a new SHAKE256 sponge cipher.
// Its generic security strength is 256 bits against all attacks if
// input keys are at least 32 bytes and output hashes are at least 64 bytes.
func NewSponge256() abstract.Sponge {
	return abstract.Sponge{&sponge{rate: 136, keyLen: 32, dsbyte: 0x1f}}
}


// ShakeSum128 writes an arbitrary-length digest of data into hash.
func ShakeSum128(hash, data []byte) {
	h := NewSponge128()
	h.Absorb(data)
	h.Squeeze(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewSponge256()
	h.Absorb(data)
	h.Squeeze(hash)
}

