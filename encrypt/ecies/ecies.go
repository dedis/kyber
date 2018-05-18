// Package ecies implements the Elliptic Curve Integrated Encryption Scheme (ECIES).
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"golang.org/x/crypto/hkdf"
)

// Encrypt first computes a shared DH key using the given public key, then
// HKDF-derives a symmetric key (and nonce) from that, and finally uses these
// values to encrypt the given message via AES-GCM. If the hash input parameter
// is nil then SHA256 is used as a default. Encrypt returns the ephemeral
// elliptic curve point of the DH key exchange and the ciphertext or an error.
func Encrypt(group kyber.Group, public kyber.Point, message []byte, hash func() hash.Hash) ([]byte, []byte, error) {
	if hash == nil {
		hash = sha256.New
	}

	// Generate an ephemeral elliptic curve scalar and point
	r := group.Scalar().Pick(random.New())
	R := group.Point().Mul(r, nil)
	Rb, err := R.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	// Compute shared DH key
	dh := group.Point().Mul(r, public)

	// Derive symmetric key and nonce via HKDF (NOTE: Since we use a new
	// ephemeral key for every ECIES encryption and thus have a fresh
	// HKDF-derived key for AES-GCM, the nonce for AES-GCM can be an arbitrary
	// (even static) value. We derive it here simply via HKDF as well.)
	len := 32 + 12
	buf, err := deriveKey(hash, dh, len)
	if err != nil {
		return nil, nil, err
	}
	key := buf[:32]
	nonce := buf[32:len]

	// Encrypt message using AES-GCM
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, message, nil)
	return Rb, ciphertext, nil
}

// Decrypt first computes a shared DH key using the received ephemeral elliptic
// curve point, then HKDF-derives a symmetric key (and nonce) from that, and
// finally uses these values to decrypt the given ciphertext via AES-GCM. If
// the hash input parameter is nil then SHA256 is used as a default. Decrypt
// returns the plaintext message or an error.
func Decrypt(group kyber.Group, private kyber.Scalar, ephPoint []byte, ciphertext []byte, hash func() hash.Hash) ([]byte, error) {
	if hash == nil {
		hash = sha256.New
	}

	// Reconstruct the ephemeral elliptic curve point
	R := group.Point()
	if err := R.UnmarshalBinary(ephPoint); err != nil {
		return nil, err
	}

	// Compute shared DH key and derive the symmetric key and nonce via HKDF
	dh := group.Point().Mul(private, R)
	len := 32 + 12
	buf, err := deriveKey(hash, dh, len)
	if err != nil {
		return nil, err
	}
	key := buf[:32]
	nonce := buf[32:len]

	// Decrypt message using AES-GCM
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func deriveKey(hash func() hash.Hash, dh kyber.Point, len int) ([]byte, error) {
	dhb, err := dh.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hkdf := hkdf.New(hash, dhb, nil, nil)
	key := make([]byte, len, len)
	n, err := hkdf.Read(key)
	if err != nil {
		return nil, err
	}
	if n < len {
		return nil, errors.New("ecies: hkdf-derived key too short")
	}
	return key, nil
}
