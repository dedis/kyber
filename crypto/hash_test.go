package crypto

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"os"

	"encoding"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
)

var hashSuite = ed25519.NewAES128SHA256Ed25519(false)

func TestHash(t *testing.T) {
	buf := make([]byte, 245)
	hashed, err := Hash(hashSuite.Hash(), buf)
	if err != nil {
		t.Fatal("Error hashing" + err.Error())
	}
	hasher := hashSuite.Hash()
	hasher.Write(buf)
	b := hasher.Sum(nil)
	if !bytes.Equal(b, hashed) {
		t.Fatal("Hashes are not equals")
	}
}

func TestHashStream(t *testing.T) {
	var buff bytes.Buffer
	str := "Hello World"
	buff.WriteString(str)
	hashed, err := HashStream(hashSuite.Hash(), &buff)
	if err != nil {
		t.Fatal("error hashing" + err.Error())
	}
	h := hashSuite.Hash()
	h.Write([]byte(str))
	b := h.Sum(nil)
	if !bytes.Equal(b, hashed) {
		t.Fatal("hashes not equal")
	}
}

func TestHashStreamAndByteEqual(t *testing.T) {
	var buff bytes.Buffer
	rb := make([]byte, 2048)
	_, _ = rand.Read(rb)
	str := string(rb)
	buff.WriteString(str)
	hashed, err := HashStream(hashSuite.Hash(), &buff)
	if err != nil {
		t.Fatal("error hashing" + err.Error())
	}

	hashed2, err := HashBytes(hashSuite.Hash(), []byte(str))
	if err != nil {
		t.Fatal("error hashing" + err.Error())
	}
	if !bytes.Equal(hashed2, hashed) {
		t.Fatal("Ouch: HashStream and HashByte differ.")
	}
}
func TestHashBytes(t *testing.T) {
	str := "Hello World"
	hashed, err := HashBytes(hashSuite.Hash(), []byte(str))
	if err != nil {
		t.Fatal("error hashing" + err.Error())
	}
	h := hashSuite.Hash()
	h.Write([]byte(str))
	b := h.Sum(nil)
	if !bytes.Equal(b, hashed) {
		t.Fatal("hashes not equal")
	}
}

func TestHashFile(t *testing.T) {
	tmpfileIO, err := ioutil.TempFile("", "hash_test.bin")
	if err != nil {
		t.Fatal(err)
	}
	tmpfileIO.Close()
	tmpfile := tmpfileIO.Name()
	defer os.Remove(tmpfile)
	for _, i := range []int{16, 128, 1024} {
		str := make([]byte, i)
		err := ioutil.WriteFile(tmpfile, str, 0777)
		if err != nil {
			t.Fatal("Couldn't write file")
		}

		hash, err := HashFile(hashSuite.Hash(), tmpfile)
		if err != nil {
			t.Fatal("Couldn't hash", tmpfile, err)
		}
		if len(hash) != 32 {
			t.Fatal("Length of sha256 should be 32")
		}
		hash2, err := HashFileSuite(hashSuite, tmpfile)
		assert.Nil(t, err)
		if bytes.Compare(hash, hash2) != 0 {
			t.Fatal("HashFile and HashFileSuite should give the same result")
		}
	}
}

func TestHashChunk(t *testing.T) {
	tmpfileIO, err := ioutil.TempFile("", "hash_test.bin")
	if err != nil {
		t.Fatal(err)
	}
	tmpfileIO.Close()
	tmpfile := tmpfileIO.Name()
	defer os.Remove(tmpfile)
	str := make([]byte, 1234)
	err = ioutil.WriteFile(tmpfile, str, 0777)
	if err != nil {
		t.Fatal("Couldn't write file")
	}

	for _, i := range []int{16, 128, 1024} {
		log.Lvl3("Reading", i, "bytes")
		hash, err := HashFileChunk(ed25519.NewAES128SHA256Ed25519(false).Hash(),
			tmpfile, i)
		if err != nil {
			t.Fatal("Couldn't hash", tmpfile, err)
		}
		if len(hash) != 32 {
			t.Fatal("Length of sha256 should be 32")
		}
	}
}

func TestHashSuite(t *testing.T) {
	var buff bytes.Buffer
	content := make([]byte, 100)
	buff.Write(content)
	var buff2 bytes.Buffer
	buff2.Write(content)
	hashed, err := HashStream(hashSuite.Hash(), &buff)
	hashedSuite, err2 := HashStreamSuite(hashSuite, &buff2)
	if err != nil || err2 != nil {
		t.Fatal("error hashing" + err.Error() + err2.Error())
	}
	if !bytes.Equal(hashed, hashedSuite) {
		t.Fatal("hashes not equals")
	}
}

func TestHashArgs(t *testing.T) {
	str1 := binstring("cosi")
	str2 := binstring("rocks")
	hash1, err := HashArgs(hashSuite.Hash(), str1)
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := HashArgs(hashSuite.Hash(), str1, str1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(hash1, hash2) == 0 {
		t.Fatal("Making a hash from a string and stringstring should be different")
	}
	hash1, _ = HashArgsSuite(hashSuite, str1, str2)
	hash2, _ = HashArgsSuite(hashSuite, str2, str1)
	if bytes.Compare(hash1, hash2) == 0 {
		t.Fatal("Making a hash from str1str2 should be different from str2str1")
	}

	X := make([]abstract.Point, 2)
	X[0] = hashSuite.Point().Base()
	X[1] = hashSuite.Point().Null()
	_, err = HashArgsSuite(hashSuite, X)
	log.ErrFatal(err)
}

func TestConvertToBinaryMarshaler(t *testing.T) {
	X := make([]abstract.Point, 2)
	X[0] = hashSuite.Point().Base()
	X[1] = hashSuite.Point().Null()

	bm, err := ConvertToBinaryMarshaler(X)
	log.ErrFatal(err)
	testEqual(t, bm[0], X[0])
	testEqual(t, bm[1], X[1])

	bm, err = ConvertToBinaryMarshaler(X[0], X[1])
	log.ErrFatal(err)
	testEqual(t, bm[0], X[0])
	testEqual(t, bm[1], X[1])

	bm, err = ConvertToBinaryMarshaler(X, X)
	log.ErrFatal(err)
	testEqual(t, bm[0], X[0])
	testEqual(t, bm[1], X[1])
	testEqual(t, bm[2], X[0])
	testEqual(t, bm[3], X[1])
}

func testEqual(t *testing.T, a, b encoding.BinaryMarshaler) {
	bina, err := a.MarshalBinary()
	log.ErrFatal(err)
	binb, err := b.MarshalBinary()
	log.ErrFatal(err)
	if !bytes.Equal(bina, binb) {
		t.Fatal("Binaries are not the same")
	}
}

type binstring string

func (b binstring) MarshalBinary() ([]byte, error) {
	return []byte(b), nil
}
