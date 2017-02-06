package hash_test

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"os"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
)

var suite = ed25519.NewAES128SHA256Ed25519(false)

func TestStream(t *testing.T) {
	var buff bytes.Buffer
	str := "Hello World"
	buff.WriteString(str)
	hashed, err := hash.Stream(suite.Hash(), &buff)
	if err != nil {
		t.Fatal(err)
	}
	h := suite.Hash()
	h.Write([]byte(str))
	b := h.Sum(nil)
	if !bytes.Equal(b, hashed) {
		t.Fatal("hashes not equal")
	}
}

func TestFile(t *testing.T) {
	tmpfileIO, err := ioutil.TempFile("", "hash_test.bin")
	if err != nil {
		t.Fatal(err)
	}
	tmpfileIO.Close()
	tmpfile := tmpfileIO.Name()
	defer os.Remove(tmpfile)
	for _, i := range []int{16, 32, 128, 1024, 1536, 2048, 10001} {
		buf := make([]byte, i)
		_, err := rand.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(tmpfile, buf, 0777); err != nil {
			t.Fatal(err)
		}
		hash, err := hash.File(suite.Hash(), tmpfile)
		if err != nil {
			t.Fatal(err)
		}
		if len(hash) != 32 {
			t.Fatal("Output of SHA256 should be 32 bytes")
		}
	}
}

func TestStructures(t *testing.T) {
	x := suite.Scalar().Pick(random.Stream)
	y := suite.Scalar().Pick(random.Stream)
	X, _ := suite.Point().Pick(nil, random.Stream)
	Y, _ := suite.Point().Pick(nil, random.Stream)

	h1, err := hash.Structures(suite.Hash(), x, y)
	if err != nil {
		t.Fatal(err)
	}

	h2, err := hash.Structures(suite.Hash(), X, Y)
	if err != nil {
		t.Fatal(err)
	}

	h3, err := hash.Structures(suite.Hash(), x, y, X, Y)
	if err != nil {
		t.Fatal(err)
	}

	h4, err := hash.Structures(suite.Hash(), x, y, X, Y, []abstract.Scalar{x, y, x}, []abstract.Point{Y, X, Y})
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(h1, h2) || bytes.Equal(h2, h3) || bytes.Equal(h3, h4) {
		t.Fatal("Unexpectably obtained equal hashes")
	}

	h5, err := hash.Structures(suite.Hash(), x, x, y, y)
	if err != nil {
		t.Fatal(err)
	}

	h6, err := hash.Structures(suite.Hash(), []abstract.Scalar{x, x, y, y})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(h5, h6) {
		t.Fatal("Hashes do not match")
	}

	h7, err := hash.Structures(suite.Hash(), X, Y, Y, X)
	if err != nil {
		t.Fatal(err)
	}

	h8, err := hash.Structures(suite.Hash(), []abstract.Point{X, Y, Y, X})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(h7, h8) {
		t.Fatal("Hashes do not match")
	}
}
