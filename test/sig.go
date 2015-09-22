package test

import (
	"bytes"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sig"
	"github.com/stretchr/testify/assert"
	"hash"
	"io"
	"testing"
)

// Generic test suite for any signature scheme
// supporting the interface defined in the crypto/sig package.
func TestSig(t *testing.T, newKey func() sig.SecretKey) {

	k1 := newKey().Pick()
	k2 := newKey().Pick()
	assert.NotEqual(t, k1.String(), k2.String())

	// Key marshaling via MarshalTo
	buf := bytes.Buffer{}
	n, err := k1.MarshalTo(&buf)
	assert.NoError(t, err)
	if rk1, ok := k1.(abstract.RigidMarshaling); ok {
		assert.Equal(t, n, rk1.MarshalSize())
	}

	// Key marshaling via BinaryMarshal
	bufc, err := k1.MarshalBinary()
	assert.NoError(t, err)
	assert.Equal(t, bufc, buf.Bytes())

	// Key unmarshaling via UnmarshalFrom
	k1c := newKey()
	nc, err := k1c.UnmarshalFrom(&buf)
	assert.NoError(t, err)
	assert.Equal(t, nc, n)
	assert.Equal(t, k1.String(), k1c.String())

	// Key unmarshaling via BinaryUnmarshal
	k1c = newKey()
	err = k1c.UnmarshalBinary(bufc)
	assert.NoError(t, err)
	assert.Equal(t, k1.String(), k1c.String())

	// Sign a simple message
	hashMsg := func() hash.Hash {
		msg := []byte("The quick brown fox jumps over the lazy dog")
		h := k1.Hash()
		n, err := h.Write(msg)
		assert.NoError(t, err)
		assert.Equal(t, n, len(msg))
		return h
	}
	h := hashMsg()
	sb, err := k1.Sign(nil, h)
	assert.NoError(t, err)
	assert.Equal(t, len(sb), k1.SigSize())

	// Verify the signature using the correct key
	p1 := k1.PublicKey()
	h = hashMsg()
	err = p1.Verify(sb, h)
	assert.NoError(t, err)

	// Verify the signature using the wrong key
	p2 := k2.PublicKey()
	h = hashMsg()
	err = p2.Verify(sb, h)
	assert.Error(t, err)

	// Try to verify using a too-short signature
	h = hashMsg()
	err = p1.Verify(sb[:len(sb)-1], h)
	assert.Error(t, err)

	// Test filter-style signing via sig.Writer
	buf.Reset()
	sigw := sig.Writer(&buf, k1)
	n, err = sigw.Write([]byte("Foobar"))
	assert.NoError(t, err)
	assert.Equal(t, n, 6)
	n, err = sigw.Write([]byte("Blah"))
	assert.NoError(t, err)
	assert.Equal(t, n, 4)
	err = sigw.Close() // append signature
	assert.NoError(t, err)
	assert.Equal(t, buf.Len(), 10+k1.SigSize())

	// Test filter-style signature verification via sig.Reader
	sigr := sig.Reader(&buf, k1)
	msg := make([]byte, 20)
	n, err = sigr.Read(msg)
	assert.NoError(t, err)
	assert.Equal(t, n, 10)
	assert.Equal(t, msg[:10], []byte("FoobarBlah"))
	n, err = sigr.Read(msg)
	assert.Equal(t, err, io.EOF)
}
