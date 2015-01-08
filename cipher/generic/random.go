package generic

import (
	"github.com/dedis/crypto/cipher"
)

// Wrapper for a cipher.Stream to provide the cipher.Random interface,
// which supports both the XORKeyStream() method from cipher.Stream
// and the more basic Read() method compatible with io.Reader.
type RandomStream struct {
	cipher.Stream
}

// Read cryptographic pseudorandom bytes from the underlying Stream.
func (rs RandomStream) Read(buf []byte) (n int, err error) {
	l := len(buf)
	for i := 0; i < l; i++ {
		buf[i] = 0
	}
	rs.XORKeyStream(buf, buf)
	return l,nil
}

