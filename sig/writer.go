package sig

import (
	"crypto/cipher"
	"github.com/dedis/crypto/random"
	"hash"
	"io"
)

// Create a Writer that interposes on underlying Writer wr,
// hashing all bytes written and appending a trailing signature on Close.
//
// The signature is assumed to be fixed-size at least for a given public key,
// and is appended to the end of the written data with no framing metadata.
// Thus we can sign arbitrary-size streaming messages efficiently,
// and the message's total size does not need to be known in advance.
func Writer(wr io.Writer, key SecretKey, rand cipher.Stream) io.WriteCloser {
	if rand == nil {
		rand = random.Stream
	}
	return &sigWriter{wr, key, key.Hash(), rand}
}

type sigWriter struct {
	w io.Writer
	k SecretKey
	h hash.Hash
	r cipher.Stream
}

func (sw *sigWriter) Write(p []byte) (int, error) {
	n, err := sw.h.Write(p)
	if n != len(p) || err != nil {
		return n, err
	}
	n, err = sw.w.Write(p)
	return n, err
}

func (sw *sigWriter) Close() error {
	if sw.h != nil {
		sb, err := sw.k.Sign(nil, sw.h, sw.r)
		if err != nil {
			return err
		}
		if len(sb) != sw.k.SigSize() { // sanity check
			panic("wrong-size signature")
		}
		n, err := sw.w.Write(sb) // append signature
		if err != nil {
			return err
		}
		if n != len(sb) {
			panic("short signature write")
		}
		sw.h = nil
	}
	if wc, ok := sw.w.(io.Closer); ok {
		return wc.Close()
	}
	return nil
}
