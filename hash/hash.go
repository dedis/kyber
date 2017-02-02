// Package hash provides utility functions to process complex data types, like
// data streams, files, or sequences of structs of different types.
package hash

import (
	"bytes"
	"errors"
	h "hash"
	"io"
	"os"

	"encoding"
	"reflect"
)

var defaultChunkSize = 1024

// Stream returns the hash of a data stream separated into chunks of the defaultChunkSize.
func Stream(hash h.Hash, stream io.Reader) ([]byte, error) {
	return StreamChunk(hash, stream, defaultChunkSize)
}

// StreamChunk returns the hash of a data stream separated into chunks of the given byte size.
func StreamChunk(hash h.Hash, stream io.Reader, size int) ([]byte, error) {
	if size < 1 {
		return nil, errors.New("Invalid chunk size")
	}
	b := make([]byte, size)
	for {
		n, errRead := stream.Read(b)
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

// File returns the hash of a file processed as a data stream of chunks of the defaultChunkSize.
func File(hash h.Hash, stream io.Reader) ([]byte, error) {
	return StreamChunk(hash, stream, defaultChunkSize)
}

// FileChunk returns the hash of a file processed as a data stream of chunks with the given byte size.
func FileChunk(hash h.Hash, file string, size int) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	return StreamChunk(hash, f, size)
}

// Args returns the hash of all the given arguments. Each argument has to
// implement the BinaryMarshaler interface.
func Args(hash h.Hash, args ...interface{}) ([]byte, error) {
	var res, buf []byte
	bmArgs, err := convertToBinaryMarshaler(args)
	if err != nil {
		return nil, err
	}
	for _, a := range bmArgs {
		buf, err = a.MarshalBinary()
		if err != nil {
			return nil, err
		}
		res, err = Stream(hash, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// convertToBinaryMarshaler takes a slice of interfaces and returns
// a slice of BinaryMarshalers.
func convertToBinaryMarshaler(args ...interface{}) ([]encoding.BinaryMarshaler, error) {
	var ret []encoding.BinaryMarshaler
	for _, a := range args {
		refl := reflect.ValueOf(a)
		if refl.Kind() == reflect.Slice {
			for b := 0; b < refl.Len(); b++ {
				el := refl.Index(b)
				bms, err := convertToBinaryMarshaler(el.Interface())
				if err != nil {
					return nil, err
				}
				ret = append(ret, bms...)
			}
		} else {
			bm, ok := a.(encoding.BinaryMarshaler)
			if !ok {
				return nil, errors.New("Could not convert to BinaryMarshaler")
			}
			ret = append(ret, bm)
		}
	}
	return ret, nil
}
