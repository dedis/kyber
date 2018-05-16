// Package ecies implements the Elliptic Curve Integrated Encryption Scheme (ECIES).
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"hash"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"golang.org/x/crypto/hkdf"
)

// Encrypt first performs a DH key exchange, then HKDF-derives a shared secret
// key (and nonce) and finally AEAD encrypts the given message using AES-GCM.
// Encrypt returns the ephemeral elliptic curve point of the DH key exchange
// and the ciphertext or an error.
func Encrypt(group kyber.Group, hash func() hash.Hash, public kyber.Point, message []byte) ([]byte, []byte, error) {
	// Generate an ephemeral key
	r := group.Scalar().Pick(random.New())
	R := group.Point().Mul(r, nil)
	Rb, err := R.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	// Compute shared DH key
	dh := group.Point().Mul(r, public)

	// Derive symmetric key and nonce via HDKF (NOTE: Since we use a new
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

// Decrypt first performs a DH key exchange using the received ephemeral
// elliptic curve point, then HKDF-derives a shared secret key (and nonce) and
// finally AEAD decrypts the given ciphertext using AES-GCM. Decrypt returns
// the plaintext message or an error.
func Decrypt(group kyber.Group, hash func() hash.Hash, private kyber.Scalar, Rb []byte, ciphertext []byte) ([]byte, error) {
	// Reconstruct ephemeral key
	R := group.Point()
	if err := R.UnmarshalBinary(Rb); err != nil {
		return nil, err
	}

	// Compute shared DH key
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
		return nil, errors.New("ECIES: HDKF-derived key too short")
	}
	return key, nil
}
