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
	assert.Equal(t, b, hashed)
}

func TestFile(t *testing.T) {
	tmpfileIO, err := ioutil.TempFile("", "hash_test.bin")
	require.Nil(t, err)
	tmpfileIO.Close()
	tmpfile := tmpfileIO.Name()
	defer os.Remove(tmpfile)
	for _, i := range []int{16, 32, 128, 1024, 1536, 2048, 10001} {
		buf := make([]byte, i)
		_, err := rand.Read(buf)
		require.Nil(t, err)
		err := ioutil.WriteFile(tmpfile, buf, 0777)
		require.Nil(t, err)
		hash, err := hash.File(suite.Hash(), tmpfile)
		require.Nil(t, err)
		require.Equal(t, 32, len(hash), "Output of SHA256 should be 32 bytes")
	}
}

func TestStructures(t *testing.T) {
	x := suite.Scalar().Pick(random.Stream)
	y := suite.Scalar().Pick(random.Stream)
	X, _ := suite.Point().Pick(nil, random.Stream)
	Y, _ := suite.Point().Pick(nil, random.Stream)

	h1, err := hash.Structures(suite.Hash(), x, y)
	require.Nil(t, err)

	h2, err := hash.Structures(suite.Hash(), X, Y)
	require.Nil(t, err)

	h3, err := hash.Structures(suite.Hash(), x, y, X, Y)
	require.Nil(t, err)

	h4, err := hash.Structures(suite.Hash(), x, y, X, Y, []abstract.Scalar{x, y, x}, []abstract.Point{Y, X, Y})
	require.Nil(t, err)

	require.Equal(t, h1, h2)
	require.Equal(t, h2, h3)
	require.Equal(t, h3, h4)

	h5, err := hash.Structures(suite.Hash(), x, x, y, y)
	require.Nil(t, err)

	h6, err := hash.Structures(suite.Hash(), []abstract.Scalar{x, x, y, y})
	require.Nil(t, err)
	require.Equal(t, h5, h6)

	h7, err := hash.Structures(suite.Hash(), X, Y, Y, X)
	require.Nil(t, err)

	h8, err := hash.Structures(suite.Hash(), []abstract.Point{X, Y, Y, X})
	require.Nil(t, err)
	require.Equal(t, h7, h8)
}
