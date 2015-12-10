package purb

import (
	//	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/aes"
	//	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/padding"
	"github.com/dedis/crypto/random"
	"io/ioutil"
	"os"
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
		edwards.NewAES128SHA256Ed25519(true),
	}

	fakery := 7
	nentries := 4
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
	hdrend, err := w.Layout(entries, random.Stream, suiteEntry)
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
		if i%2 == 0 {
			continue
		}
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
func TestWritePurb(t *testing.T) {
	//simple test with one suite
	suite := edwards.NewAES128SHA256Ed25519(true)
	nentries := 3
	entries := make([]Entry, 0)
	suiteEntry := make(map[abstract.Suite][]int)
	nlevels := 1
	ents := make([]int, nlevels)
	for j := 0; j < nlevels; j++ {
		ents[j] = j * ENTRYLEN
	}
	suiteEntry[suite] = ents
	// Create some entrypoints with this suite
	s := suite
	for j := 0; j < nentries; j++ {
		pri := s.Secret().Pick(random.Stream)
		pub := s.Point().Mul(nil, pri)
		data := make([]byte, DATALEN)
		entries = append(entries, Entry{s, pri, pub, data})
	}
	msg := "This is the message! It will be stored as a file!!"
	writePurb(entries, suiteEntry, []byte(msg), "test.purb")
	file, _ := os.Create("keyfile1")
	i, err := entries[0].PriKey.MarshalTo(file)
	file, _ = os.Create("keyfile2")
	i, err = entries[1].PriKey.MarshalTo(file)
	file, _ = os.Create("keyfile3")
	i, err = entries[2].PriKey.MarshalTo(file)
	if err != nil {
		fmt.Println(err, i)
	}
}

//Reads single ed25519 private keys from single files
func TestReadPurbFromFile(t *testing.T) {
	//get a public key
	//Problem need to know the suite already I think.
	suite := edwards.NewAES128SHA256Ed25519(true)
	suiteEntry := make(map[abstract.Suite][]int)
	nlevels := 1
	ents := make([]int, nlevels)
	for j := 0; j < nlevels; j++ {
		ents[j] = j * ENTRYLEN
	}
	suiteEntry[suite] = ents
	file, err := os.Open("keyfile1")
	priKey := suite.Secret()
	something, err := priKey.UnmarshalFrom(file)
	if err != nil {
		fmt.Println(something, err)
	}
	encFile := make([]byte, 0)
	encFile, err = ioutil.ReadFile("test.purb")
	fmt.Println(err)
	_, msgL := attemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	file, err = os.Open("keyfile2")
	something, err = priKey.UnmarshalFrom(file)
	_, msgL = attemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	file, err = os.Open("keyfile3")
	something, err = priKey.UnmarshalFrom(file)
	_, msgL = attemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	fmt.Println(something)
}

/*Possibly should do this later, but there is only one suite we can test with at this point.
func TestConfig(t *testing.T) {
	//Create a few keys.
	suite := edwards.NewAES128SHA256Ed25519(true)
}*/
