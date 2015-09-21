package sig

import (
	"hash"
	"io"
)

// Create a Writer that interposes on underlying Writer wr,
// hashing all bytes written and appending a trailing signature on Close.
func Writer(wr io.Writer, key SecretKey) io.WriteCloser {
	return &sigWriter{wr, key, key.Hash()}
}

type sigWriter struct {
	w io.Writer
	k SecretKey
	h hash.Hash
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
		sb, err := sw.k.Sign(nil, sw.h)
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
