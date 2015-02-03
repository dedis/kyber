package cipher

import (
	"crypto/cipher"
	"crypto/hmac"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
	"github.com/dedis/crypto/random"
	"hash"
)

type streamCipher struct {

	// Configuration state
	newStream                 func(key []byte) cipher.Stream
	newHash                   func() hash.Hash
	blockLen, keyLen, hashLen int

	// Per-message cipher state
	k []byte        // master secret state from last message, 0 if unkeyed
	h hash.Hash     // hash or hmac for absorbing input
	s cipher.Stream // stream cipher for encrypting, nil if none
}

const bufLen = 1024

var zeroBytes = make([]byte, bufLen)

// Construct a general message Cipher
// from a Stream cipher and a cryptographic Hash.
func FromStream(newStream func(key []byte) cipher.Stream,
	newHash func() hash.Hash, blockLen, keyLen, hashLen int,
	key []byte, options ...interface{}) abstract.Cipher {

	sc := streamCipher{}
	sc.newStream = newStream
	sc.newHash = newHash
	sc.blockLen = blockLen
	sc.keyLen = keyLen
	sc.hashLen = hashLen
	sc.h = sc.newHash()

	if key == nil {
		key = random.Bytes(hashLen, random.Stream)
	}
	if len(key) > 0 {
		sc.Message(nil, nil, key)
	}

	if len(options) > 0 {
		panic("no FromStream options supported yet")
	}

	return &sc
}

func (sc *streamCipher) Partial(dst, src, key []byte) abstract.Cipher {

	n := ints.Max(len(dst), len(src), len(key)) // bytes to process

	// create our Stream cipher if needed
	if sc.s == nil {
		if sc.k == nil {
			sc.k = make([]byte, sc.hashLen)
		}
		sc.s = sc.newStream(sc.k[:sc.keyLen])
	}

	// squeeze cryptographic output
	ndst := ints.Min(n, len(dst))    // # bytes to write to dst
	nsrc := ints.Min(ndst, len(src)) // # src bytes available
	for i := 0; i < nsrc; i++ {      // XOR-encrypt from src to dst
		sc.s.XORKeyStream(dst[:nsrc], src[:nsrc])
	}
	if n > nsrc {
		buf := make([]byte, n-nsrc)
		sc.s.XORKeyStream(buf, buf)
		copy(dst[nsrc:], buf)
	}

	// absorb cryptographic input (which may overlap with dst)
	nkey := ints.Min(n, len(key)) // # key bytes available
	sc.h.Write(key[:nkey])
	if n > nkey {
		buf := make([]byte, n-nkey)
		sc.h.Write(buf)
	}

	return sc
}

func (sc *streamCipher) Message(dst, src, key []byte) abstract.Cipher {
	sc.Partial(dst, src, key)

	sc.k = sc.h.Sum(sc.k[:0])         // update state with absorbed data
	sc.h = hmac.New(sc.newHash, sc.k) // ready for next msg
	sc.s = nil                        // create a fresh stream cipher

	return sc
}

func (sc *streamCipher) Read(dst []byte) (n int, err error) {
	sc.Partial(dst, nil, nil)
	return len(dst), nil
}

func (sc *streamCipher) Write(key []byte) (n int, err error) {
	sc.Partial(nil, nil, key)
	return len(key), nil
}

func (sc *streamCipher) XORKeyStream(dst, src []byte) {
	sc.Partial(dst[:len(src)], src, nil)
}

func (sc *streamCipher) KeySize() int {
	return sc.keyLen
}

func (sc *streamCipher) HashSize() int {
	return sc.hashLen
}

func (sc *streamCipher) BlockSize() int {
	return sc.blockLen
}

func (sc *streamCipher) Fork(nsubs int) []abstract.Cipher {
	panic("XXX not yet implemented")
}

func (sc *streamCipher) Join(subs ...abstract.Cipher) {
	panic("XXX not yet implemented")
}

func (sc *streamCipher) Clone() abstract.Cipher {
	if sc.s != nil {
		panic("cannot clone cipher state mid-message")
	}

	nsc := *sc
	if sc.k != nil { // keyed state
		nsc.k = make([]byte, sc.hashLen)
		copy(nsc.k, sc.k)
		nsc.h = hmac.New(nsc.newHash, nsc.k)
	} else { // unkeyed state
		nsc.h = nsc.newHash()
	}

	return &nsc
}
