package tbls

import (
	"bytes"
	"encoding/binary"

	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/share"
	"github.com/dedis/kyber/sign/bls"
)

// SigShare encodes a threshold BLS signature share s = i || v where the 2-byte
// big-endian value i corresponds to the share's index and v represents the
// share's value.
type SigShare []byte

// Index returns the index i of the TBLS share.
func (s *SigShare) Index() (int, error) {
	var index uint16
	buf := bytes.NewReader([]byte(*s))
	err := binary.Read(buf, binary.BigEndian, &index)
	if err != nil {
		return -1, err
	}
	return int(index), nil
}

// Value returns the value v of the TBLS share.
func (s *SigShare) Value() []byte {
	return []byte(*s)[2:]
}

// Sign creates a threshold BLS signature si = xi * H(m) on the given message m
// using the provided secret key share xi.
func Sign(suite pairing.Suite, private *share.PriShare, msg []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(private.I)); err != nil {
		return nil, err
	}
	s, err := bls.Sign(suite, private.V, msg)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks the given threshold BLS signature si on the message m using
// the public key share Xi that is associated to the secret key share xi. This
// public key share Xi can be computed by evaluating the public sharing
// polynonmial at the share's index i.
func Verify(suite pairing.Suite, public *share.PubPoly, msg, sig []byte) error {
	s := SigShare(sig)
	i, err := s.Index()
	if err != nil {
		return err
	}
	return bls.Verify(suite, public.Eval(i).V, msg, s.Value())
}

// Recover reconstructs the full BLS signature s = x * H(m) from a threshold t
// of signature shares si using Lagrange interpolation. The full signature s
// can be verified through the regular BLS verification routine using the
// shared public key X. The shared public key can be computed by evaluating the
// public sharing polynomial at index 0.
func Recover(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := SigShare(sig)
		i, err := s.Index()
		if err != nil {
			return nil, err
		}
		if err = bls.Verify(suite, public.Eval(i).V, msg, s.Value()); err != nil {
			return nil, err
		}
		point := suite.G1().Point()
		if err := point.UnmarshalBinary(s.Value()); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	commit, err := share.RecoverCommit(suite.G1(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}
