package util

import (
	"io"
	"bytes"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestMessageReader(t *testing.T) {
	head := make([]byte, 3)
	tail := make([]byte, 3)
	body := make([]byte, 1024)

	// Simple message with 3-byte head and tail
	m := []byte("The quick brown fox jumps over the lazy dog")
	n, err := MessageReader(bytes.NewReader(m), head, tail).Read(body)
	assert.NoError(t, err)
	assert.Equal(t, n, len(m)-3-3)
	assert.Equal(t, body[:len(m)-3-3], m[3:len(m)-3])

	// Message with empty body
	m = []byte("foobar")
	n, err = MessageReader(bytes.NewReader(m), head, tail).Read(body)
	assert.Equal(t, n, 0)
	assert.Equal(t, err, io.EOF)

	// Too-short message
	m = []byte("fooba")
	n, err = MessageReader(bytes.NewReader(m), head, tail).Read(body)
	assert.Error(t, err)
	assert.Equal(t, n, 0)

	// Large message with moderately-large head and tail
	mlen := 1024*1024
	m = make([]byte, mlen)
	for i := 0; i < mlen; i++ {
		m[i] = byte(mlen)
	}
	head = make([]byte, 16*1024)
	tail = make([]byte, 16*1024)
	body = make([]byte, len(m))
	mb := m[len(head):len(m)-len(tail)]
	mr := MessageReader(bytes.NewReader(m), head, tail)
	tot := 0
	for {
		n, err = mr.Read(body)
		if n <= 0 {
			break
		}
		assert.NotEqual(t, n, len(m)-len(head)-len(body))
		assert.Equal(t, body[:n], mb[:n])
		mb = mb[n:]
		tot += n
	}
	assert.Equal(t, tot, mlen-len(head)-len(tail))
	assert.Equal(t, err, io.EOF)
	assert.Equal(t, head, m[:len(head)])
	assert.Equal(t, tail, m[len(m)-len(tail):])
}

