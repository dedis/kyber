package sig

import (
	"github.com/dedis/crypto/util"
	"hash"
	"io"
)

// Create a Reader that interposes on underlying Reader rd,
// hashing all bytes read and verifying a trailing signature.
// Never returns normal io.EOF status unless the signature checks.
//
// Since Writer does not add any framing metadata other than the signature,
// the Reader treats the fixed-length signature as a self-delimiting tail.
// The signature is only checked during a Read call in which
// the underlying Reader has already returned an EOF condition
// and there is no further message-body data to return to the caller.
//
// Provided the caller processes body data immediately upon reading,
// the public key against which the signature is to be verified
// can be part of the message being decoded.
// This capability can be useful for validating self-signed certificates.
//
func Reader(rd io.Reader, key PublicKey) io.Reader {
	sb := make([]byte, key.SigSize())
	h := key.Hash()
	mr := util.MessageReader(rd, nil, sb)
	return &sigReader{mr, key, h, sb, nil}
}

type sigReader struct {
	r   io.Reader // MessageReader to separate body from signature
	k   PublicKey // Public key for signature verification
	h   hash.Hash // Hash used to check message body
	sb  []byte    // Signature buffer
	err error     // Final signature-check status on EOF
}

func (sr *sigReader) Read(p []byte) (int, error) {
	if sr.err != nil {
		return 0, sr.err // sticky final status on EOF
	}

	// Read message data until EOF
	n, err := sr.r.Read(p)
	if n > 0 {
		hn, err := sr.h.Write(p[:n])
		if err != nil {
			return 0, err
		}
		if hn != n {
			panic("short hash write")
		}
		return n, nil
	}

	// Perform signature-check on regular EOF
	if err == io.EOF {
		e := sr.k.Verify(sr.sb, sr.h)
		if e != nil {
			err = e // signature verification failure
		}
	}
	sr.err = err // sticky final status (io.EOF or other error)
	return 0, err
}
