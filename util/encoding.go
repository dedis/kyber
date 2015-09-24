package util

import (
	"bytes"
	"encoding/binary"
)

// Helpers functions regarding the encoding of basic types ( integers ...)

// We will work with INT32 integer for now
// Transform a int value to a buffer
func Int2Buf(i int) ([]byte, error) {
	val := int64(i)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, val)
	return buf.Bytes(), err
}

// Returns the int value with the number of byte read
// Check encoding/binary.Uvarint for more precisions
func Buf2Int(buf []byte) (int, error) {
	var val int64
	size := binary.Size(val)
	b := bytes.NewReader(buf[0:size])
	err := binary.Read(b, binary.LittleEndian, &val)
	return int(val), err
}

func IntSize(val int) int {
	return binary.Size(int64(val))
}

func UInt64ToBuf(val uint64) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, val)
	return buf.Bytes(), err
}

// Returns the int value with the number of byte read
// Check encoding/binary.Uvarint for more precisions
func BufToUInt64(buf []byte) (int, error) {
	var val uint64
	size := binary.Size(val)
	b := bytes.NewReader(buf[0:size])
	err := binary.Read(b, binary.LittleEndian, &val)
	return int(val), err
}

func UInt64Size(val uint64) int {
	return binary.Size(uint64(val))
}
