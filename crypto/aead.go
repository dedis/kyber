package crypto

import (
	"crypto/cipher"
	"misc"
)

// Wrapper for a Sponge cipher to provide the 
// Authenticated Encryption with Additional Data (AEAD) interface.

func (a aead) NonceSize() int {
	return a.KeyLen()
}

func (a aead) Overhead() int {
	return a.KeyLen()
}

func (a aead) Seal(dst, nonce, msg, hdr []byte) []byte {
	s := a.Clone()
	s.Write(nonce)
	s.Write(hdr)

	dst,ctx := misc.Grow(dst, len(msg))
	s.Encrypt(ctx, msg)

	dst,mac := misc.Grow(dst, s.KeyLen())
	s.Read(mac)
	return dst
}

func (a aead) Open(dst, nonce, ctx, hdr []byte) ([]byte, error) {
	s := a.Clone()
	kl := s.KeyLen()
	ml := len(ctx) - kl
	if ml < 0 {
		return nil,errors.New("AEAD ciphertext too short")
	}
	s.Write(nonce)
	s.Write(hdr)

	dst,msg := misc.Grow(dst, ml)
	s.Decrypt(msg, ctx[:ml])

	mac := make([]byte, kl)
	s.Read(mac)
	if subtle.ConstantTimeCompare(mac, ctx[ml:]) == 0 {
		return nil,errors.New("AEAD authentication check failed")
	}

	return dst,nil
}

