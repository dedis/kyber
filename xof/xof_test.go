package xof

import (
	"bytes"
	"math"
	"testing"
)

func TestEncDec(t *testing.T) {
	tests := [][]byte{
		[]byte(""),
		[]byte("Hello world."),
		make([]byte, 72),
		make([]byte, 73),
		make([]byte, 1*1024),
		make([]byte, 8*1024),
	}

	for i := range sponges {
		testKeying(t, i)
		testRandom(t, i)
		for _, tt := range tests {
			testEncDec(t, i, tt)
		}
	}
}

func testEncDec(t *testing.T, name string, msg []byte) {
	// Test round trip of encrypt/decrypt
	key1 := []byte("key")
	key2 := []byte("yek")
	xof1 := NewByName(name)
	xof2 := NewByName(name)
	xof3 := NewByName(name)
	xof1.Absorb(key1)
	xof2.Absorb(key1)
	xof3.Absorb(key2)

	t.Logf("enc/dec sponge %T, len(msg)=%v", xof1.(*xofSponge).sponge, len(msg))

	enc := make([]byte, len(msg)+10)

	// Write sentinel bytes to the end of enc
	sentinel := make([]byte, 10)
	for i := range sentinel {
		sentinel[i] = byte(i)
	}
	copy(enc[len(msg):], sentinel)

	xof1.XORKeyStream(enc, msg)
	if len(msg) > 0 && bytes.Equal(enc[:len(msg)], msg) {
		t.Fatal("not encrypted")
	}
	// Check sentinel bytes.
	if !bytes.Equal(enc[len(msg):], sentinel) {
		t.Fatal("end of enc was modified")
	}

	out1 := make([]byte, len(msg))
	xof2.XORKeyStream(out1, enc[:len(msg)])
	if !bytes.Equal(out1, msg) {
		t.Fatal("not decrypted correctly")
	}

	// decrypt with xof keyed to another key
	// is not correct.
	out2 := make([]byte, len(msg))
	xof3.XORKeyStream(out2, enc[:len(msg)])
	if len(msg) > 0 && bytes.Equal(out2, msg) {
		t.Fatal("decrypt with wrong key should not give original message")
	}
}

func testKeying(t *testing.T, name string) {
	key := []byte("a nice big juicy key")

	xof1 := NewByName(name)
	xof1.Absorb(key)
	xof2 := NewByName(name)
	xof2.Absorb(key)
	xof3 := NewByName(name)
	xof3.Absorb(key[0:1])
	xof3.Absorb(key[1:])

	t.Logf("keying sponge %T", xof1.(*xofSponge).sponge)

	dst1 := make([]byte, 100)
	xof1.Extract(dst1)
	dst2 := make([]byte, 100)
	xof2.Extract(dst2)
	if !bytes.Equal(dst1, dst2) {
		t.Fatal("same keyed XOFs should make the same key stream")
	}

	dst3 := make([]byte, 100)
	xof3.Extract(dst3)
	if bytes.Equal(dst1, dst3) {
		t.Fatal("differently keyed XOFs should not make the same key stream")
	}
}

func testRandom(t *testing.T, name string) {
	xof1 := NewByName(name)
	t.Logf("random sponge %T", xof1.(*xofSponge).sponge)

	for i := 0; i < 1000; i++ {
		dst1 := make([]byte, 1024)
		xof1.Extract(dst1)
		dst2 := make([]byte, 1024)
		xof1.Extract(dst2)
		d := bitDiff(dst1, dst2)
		if math.Abs(d-0.50) > 0.1 {
			t.Fatalf("bitDiff %v", d)
		}
		xof1.Absorb(dst1)
		xof1.Absorb(dst2)
	}
}

// bitDiff compares the bits between two arrays returning the fraction
// of differences. If the two arrays are not of the same length
// no comparison is made and a -1 is returned.
func bitDiff(a, b []byte) float64 {
	if len(a) != len(b) {
		return -1
	}

	count := 0
	for i := 0; i < len(a); i++ {
		for j := 0; j < 8; j++ {
			count += int(((a[i] ^ b[i]) >> uint(j)) & 1)
		}
	}

	return float64(count) / float64(len(a)*8)
}
