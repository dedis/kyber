package purb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/aes"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/padding"
	"github.com/dedis/crypto/random"
	"io/ioutil"
	"testing"
)

// Simple harness to create lots of fake ciphersuites out of a few real ones,
// for testing purposes.
type fakeSuite struct {
	abstract.Suite
	idx int
}

func (f *fakeSuite) String() string {
	return fmt.Sprintf("%s(%d)", f.Suite.String(), f.idx)
}

func TestPurb(t *testing.T) {

	realSuites := []abstract.Suite{
		//nist.NewAES128SHA256QR512(),
		edwards.NewAES128SHA256Ed25519(true),
	}
	fmt.Println(realSuites[0])

	fakery := 10
	nentries := 10
	datalen := DATALEN

	suites := make([]abstract.Suite, 0)
	for i := range realSuites {
		real := realSuites[i]
		for j := 0; j < fakery; j++ {
			suites = append(suites, &fakeSuite{real, j})
		}
	}

	nlevels := 5
	suiteLevel := make(map[abstract.Suite]int)
	entries := make([]Entry, 0)
	suiteEntry := make(map[abstract.Suite][]int)
	for i := range suites {
		suiteLevel[suites[i]] = nlevels
		nlevels++ // vary it a bit for testing
		ents := make([]int, nlevels)
		for j := 0; j < nlevels; j++ {
			ents[j] = j * ENTRYLEN
		}
		suiteEntry[suites[i]] = ents

		// Create some entrypoints with this suite
		s := suites[i]
		for j := 0; j < nentries; j++ {
			pri := s.Secret().Pick(random.Stream)
			pub := s.Point().Mul(nil, pri)
			data := make([]byte, datalen)
			entries = append(entries, Entry{s, pri, pub, data})
		}
	}

	w := Writer{}
	hdrend, err := w.Layout(suiteLevel, entries, random.Stream, suiteEntry)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	key, _ := hex.DecodeString("9a4fea86a621a91ab371e492457796c0")
	//Probably insecure way to use it.

	cipher := abstract.Cipher(aes.NewCipher128(key))
	msg := []byte("This is the message!")
	//from testing
	encOverhead := 16
	msg = padding.PadGeneric(msg, encOverhead+hdrend)
	enc := make([]byte, 0)
	enc = cipher.Seal(enc, msg)
	//encrypt message
	//w.layout.reserve(hdrend, hdrend+len(msg), true, "message")
	//Now test Write, need to fill all entry point
	fmt.Println("Writing Message")
	byteLen := make([]byte, 8)
	binary.BigEndian.PutUint64(byteLen, uint64(hdrend))
	for i := range w.entries {
		w.entries[i].Data = append(byteLen, key...)
	}
	encMessage := w.Write(random.Stream)
	fmt.Println(len(encMessage), hdrend)
	encMessage = append(encMessage, enc...)
	fmt.Println(len(encMessage))
	err = ioutil.WriteFile("test.bin", encMessage, 0644)
	if err != nil {
		panic(err)
	}
	//Now test the decoding.
	encFile := make([]byte, 0)
	encFile, err = ioutil.ReadFile("test.bin")
	if err != nil {
		panic(err)
	}
	for i := range entries {
		ent := entries[i]
		_, msgL := attemptDecode(ent.Suite, ent.PriKey, suiteEntry, encFile, random.Stream)
		if msgL == nil {
			fmt.Println("Could not decrypt", ent)
			continue
		}
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
}
func TestPlaceHash(t *testing.T) {
	w := Writer{}
	w.layout.reset()

	for i := uint(0); i < 8; i++ {
		fmt.Println("hash:", i)
		w.PlaceHash(i)
	}
	fmt.Println("hash test layout")
	w.layout.dump()
}
