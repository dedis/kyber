// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file defines the ShakeHash interface, and provides
// functions for creating SHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.

import (
	"io"
	"hash"
	"crypto/cipher"
)

type Sponge interface {
	// Hash interface for absorbing message data.
	// Consecutive calls to Write constitute a single message,
	// terminated by the next call to Read or Duplex.
	hash.Hash

	// Read reads output from the sponge,
	// after consuming the remainder any message absorbed via Write.
	// Reading affects the sponge's state, in contrast with Hash.Sum.
	// Never returns an error.
	io.Reader

	// XORKeyStream uses output from the sponge to encrypt a plaintext.
	cipher.Stream

	// Return the recommended size of symmetric cryptographic keys
	// to obtain the full security from this sponge.
	KeyLen() int

	// Concurrently absorb a message and produce a cipher-stream.
	// The generated cipher-stream bits may depend on 
	// some, all, or none of the concurrently absorbed message bits.
	// If src != nil, XORs cipher-stream bytes with src into dst.
	// If src == nil, just copies cipher-stream bytes into dst.
	Duplex(dst,src,absorb []byte)

	// Set this Sponge's state to be a clone of another Sponge,
	// then returns the target.
	Set(src Sponge) Sponge
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() ShakeHash { return &state{rate: 168, dsbyte: 0x1f} }

// NewShake256 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() ShakeHash { return &state{rate: 136, dsbyte: 0x1f} }

// ShakeSum128 writes an arbitrary-length digest of data into hash.
func ShakeSum128(hash, data []byte) {
	h := NewShake128()
	h.Write(data)
	h.Read(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	h.Write(data)
	h.Read(hash)
}

