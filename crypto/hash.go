package crypto

import (
	"bytes"
	"errors"
	h "hash"
	"io"
	"os"

	"encoding"
	"reflect"

	"github.com/dedis/onet/log"
	"gopkg.in/dedis/crypto.v0/abstract"
)

// Hash simply returns the Hash of the slice of bytes given
func Hash(hash h.Hash, buff []byte) ([]byte, error) {
	_, err := hash.Write(buff)
	return hash.Sum(nil), err
}

// DefaultChunkSize is the size of the chunk  used to read a stream
const DefaultChunkSize = 1024

// hashStream hashes a stream reading from it by chunks of DefaultChunkSize size.
func hashStream(hash h.Hash, stream io.Reader, size int) ([]byte, error) {
	b := make([]byte, size)
	for {
		n, errRead := stream.Read(b)
		log.Lvl4("Read", n, "bytes of", size)
		_, err := hash.Write(b[:n])
		if err != nil {
			return nil, err
		}
		if errRead == io.EOF || n < size {
			break
		}
	}
	return hash.Sum(nil), nil
}

// HashStream returns the hash of the stream reading from it chunk by chunk of
// size DefaultChunkSize
func HashStream(hash h.Hash, stream io.Reader) ([]byte, error) {
	return hashStream(hash, stream, DefaultChunkSize)
}

// HashBytes returns the hash of the bytes
func HashBytes(hash h.Hash, b []byte) ([]byte, error) {
	return HashStream(hash, bytes.NewReader(b))
}

// HashStreamChunk will hash the stream using chunks of size chunkSize
func HashStreamChunk(hash h.Hash, stream io.Reader, chunkSize int) ([]byte, error) {
	if chunkSize < 1 {
		return nil, errors.New("Wrong chunksize value")
	}
	return hashStream(hash, stream, chunkSize)
}

// HashFile will hash the file using the streaming approach with
// DefaultChunkSize size of chunks
func HashFile(hash h.Hash, file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	return HashStream(hash, f)

}

// HashFileChunk is similar to HashFile but using a chunkSize size of chunks for
// reading.
func HashFileChunk(hash h.Hash, file string, chunkSize int) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	return HashStreamChunk(hash, f, chunkSize)
}

// HashStreamSuite will hash the stream using the hashing function of the suite
func HashStreamSuite(suite abstract.Suite, stream io.Reader) ([]byte, error) {
	return HashStream(suite.Hash(), stream)
}

// HashFileSuite returns the hash of a file using the hashing function of the
// suite given.
func HashFileSuite(suite abstract.Suite, file string) ([]byte, error) {
	return HashFile(suite.Hash(), file)
}

// HashArgs takes all args and returns the hash. Every arg has to implement
// BinaryMarshaler.
func HashArgs(hash h.Hash, args ...interface{}) ([]byte, error) {
	var res, buf []byte
	bmArgs, err := ConvertToBinaryMarshaler(args)
	if err != nil {
		return nil, err
	}
	for _, a := range bmArgs {
		buf, err = a.MarshalBinary()
		if err != nil {
			return nil, err
		}
		res, err = HashBytes(hash, buf)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// HashArgsSuite makes a new hash from the suite and calls HashArgs
func HashArgsSuite(suite abstract.Suite, args ...interface{}) ([]byte, error) {
	return HashArgs(suite.Hash(), args...)
}

// ConvertToBinaryMarshaler takes a slice of interfaces and returns
// a slice of BinaryMarshalers
func ConvertToBinaryMarshaler(args ...interface{}) ([]encoding.BinaryMarshaler, error) {
	var ret []encoding.BinaryMarshaler
	for _, a := range args {
		refl := reflect.ValueOf(a)
		if refl.Kind() == reflect.Slice {
			for b := 0; b < refl.Len(); b++ {
				el := refl.Index(b)
				bms, err := ConvertToBinaryMarshaler(el.Interface())
				if err != nil {
					return nil, err
				}
				ret = append(ret, bms...)
			}
		} else {
			bm, ok := a.(encoding.BinaryMarshaler)
			if !ok {
				return nil, errors.New("Couldn't convert to BinaryMarshaler")
			}
			ret = append(ret, bm)
		}
	}
	return ret, nil
}
