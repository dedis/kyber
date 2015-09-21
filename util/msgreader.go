package util

import (
	"io"
	"bufio"
	"errors"
	"github.com/dedis/crypto/ints"
)

// MessageReader returns a Reader that reads from rd
// a message consisting of a head, body, and tail.
// The head and tail are assumed to be of fixed sizes
// as determined by the provided byte-slices,
// either or both of which may be zero-length or nil.
// The body is assumed to comprise the rest of the message,
// and is returned via calls to the Read method.
//
// The client may assume head and tail are valid and filled-in
// only after a body Read call returns EOF.
// Large message bodies are supported efficiently via streaming.
//
// Internally, wraps the passed Reader rd in a bufio.Reader,
// if it is not already a bufio.Reader of sufficient size.
//
func MessageReader(rd io.Reader, head []byte, tail []byte) io.Reader {

	// Wrap the underlying reader in a bufio.Reader,
	// but only if it isn't one already.
	buf, ok := rd.(*bufio.Reader)
	if !ok {
		buf = bufio.NewReader(rd)
	}

	// Also, make sure its size is at least twice the length of the tail,
	// since we must always hold len(tail) trailing bytes while reading.
	buf = bufio.NewReaderSize(buf, len(tail)*2)

	return &msgReader{buf, head, tail}
}

type msgReader struct {
	buf *bufio.Reader	// Buffer wrapping underlying io.Reader
	head []byte		// Header buffer or nil
	tail []byte		// Tailer buffer or nil
}

func (br *msgReader) Read(p []byte) (int, error) {

	// Read the full header before doing anything else
	for len(br.head) > 0 {
		n, err := br.buf.Read(br.head)
		if n <= 0 {
			return 0, msgReaderError(err)
		}
		br.head = br.head[n:]
	}

	// Read the body while always keeping len(tail) bytes buffered
	if len(p) <= 0 {
		return 0, nil
	}

	// Fill buf to contain at least one non-tail byte.
	tlen := len(br.tail)
	b, err := br.buf.Peek(tlen+1)
	if len(b) < tlen {
		// Couldn't even get a full trailer: message too short.
		return 0, msgReaderError(err)
	} else if len(b) == tlen {
		// Buffering a full tail but no more: must be EOF.
		n, _ := br.buf.Read(br.tail)
		if n != tlen { // shouldn't happen
			panic("Can't read already-peeked bytes!?")
		}
		if err == nil {
			err = io.EOF
		}
		br.tail = nil	// count the tail as having been read
		return 0, err
	}

	// We have at least one byte beyond the tail buffered.
	// Return as much as we have while reserving tail bytes.
	n := ints.Min(br.buf.Buffered() - tlen, len(p))
	rn, _ := br.buf.Read(p[:n])
	if rn != n { // shouldn't happen
		panic("Can't read already-buffered bytes!?")
	}
	return n, nil
}

func msgReaderError(err error) error {
	if err == nil || err == io.EOF {
		err = errTooShort
	}
	return err
}

var errTooShort = errors.New("message too short")

