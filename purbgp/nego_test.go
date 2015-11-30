package purb

import (
	"encoding/binary"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
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
			entries = append(entries, Entry{s, pub, data})
		}
	}

	w := Writer{}
	hdrend, err := w.Layout(suiteLevel, entries, random.Stream, suiteEntry)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	msg := "This is the message!"
	//encrypt message
	w.layout.reserve(hdrend, hdrend+len(msg), true, "message")
	//Now test Write, need to fill all entry point
	fmt.Println("Writing Message")
	byteLen := make([]byte, 8)
	binary.BigEndian.PutUint64(byteLen, uint64(hdrend))
	for i := range w.entries {
		w.entries[i].Data = append(byteLen, []byte("????????????????")...)
	}
	encMessage := w.Write(random.Stream)
	fmt.Println(len(encMessage))
}
func TestPlaceHash(t *testing.T) {
	w := Writer{}
	w.layout.reset()

	for i := 0; i < 8; i++ {
		fmt.Println("hash:", i)
		w.PlaceHash(i, DATALEN)
	}
	fmt.Println("hash test layout")
	w.layout.dump()
}
