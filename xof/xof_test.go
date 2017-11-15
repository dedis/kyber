package xof

import (
	"bytes"
	"testing"

	"github.com/dedis/kyber/cipher/norx"
	"github.com/dedis/kyber/cipher/sha3"
)

func TestXof(t *testing.T) {
	zeros1k := make([]byte, 1024)
	zeros8k := make([]byte, 8*1024)

	tests := [][]byte{
		//[]byte(""),
		[]byte("Hello world."), zeros1k, zeros8k,
	}

	for _, tt := range tests {
		testXof(t, func() Sponge { return sha3.NewKeccak1024() }, tt)
		testXof(t, func() Sponge { return norx.NewSponge() }, tt)
	}
}

func testXof(t *testing.T, mkSponge func() Sponge, msg []byte) {
	// Test round trip of encrypt/decrypt
	key := []byte("key")
	xof1 := FromSponge(mkSponge())
	xof2 := FromSponge(mkSponge())
	for i := 0; i < xof2.Rate(); i += len(key) {
		// Test absorbing in several passes
		xof1.Absorb(key[0:1])
		xof1.Absorb(key[1:])
		// Or all at once
		xof2.Absorb(key)
	}
	t.Logf("testing sponge %T, len(msg)=%v", xof1.(*xofSponge).sponge, len(msg))

	enc := make([]byte, len(msg)+10)

	// Write sentinel bytes to the end of enc
	ffs := make([]byte, 10)
	for i := range ffs {
		ffs[i] = byte(i)
	}
	copy(enc[len(msg):], ffs)

	for i := 0; i < xof1.Rate(); i += len(key) {
		xof1.Absorb(key)
	}
	xof1.XORKeyStream(enc, msg)
	if bytes.Equal(enc[:len(msg)], msg) {
		t.Fatal("not encrypted")
	}
	// Check sentinel bytes.
	if !bytes.Equal(enc[len(msg):], ffs) {
		t.Fatal("end of enc was modified")
	}

	out := make([]byte, len(msg))
	xof2.XORKeyStream(out, enc[:len(msg)])
	if !bytes.Equal(out, msg) {
		t.Fatal("not decrypted correctly")
	}
}

// Todo:
// quality of keystream output bytes
// roundtrip other sizes, including len(msg) > Rate (transform X times during op)
