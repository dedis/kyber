package tbls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/share"
	"github.com/dedis/kyber/sign/bls"
)

// SigShare ...
type SigShare []byte

// Index ...
func (s *SigShare) Index() (int, error) {
	var index uint16
	buf := bytes.NewReader([]byte(*s))
	err := binary.Read(buf, binary.BigEndian, &index)
	if err != nil {
		return -1, err
	}
	return int(index), nil
}

// Sign ...
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

// Verify ...
func Verify(suite pairing.Suite, public *share.PubPoly, msg, sig []byte) error {
	s := SigShare(sig)
	i, err := s.Index()
	if err != nil {
		return err
	}
	m := suite.G1().Point().MarshalSize()
	return bls.Verify(suite, public.Eval(i).V, msg, sig[2:m+2])
}

// Recover ...
func Recover(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := SigShare(sig)
		i, err := s.Index()
		if err != nil {
			return nil, err
		}
		m := suite.G1().Point().MarshalSize()
		if err = bls.Verify(suite, public.Eval(i).V, msg, sig[2:m+2]); err != nil {
			return nil, err
		}
		point := suite.G1().Point()
		if err := point.UnmarshalBinary(sig[2 : m+2]); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	if len(pubShares) < t {
		return nil, errors.New("tbls: not enough valid signature shares")
	}
	//return pubShares, nil
	commit, err := share.RecoverCommit(suite.G1(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	fmt.Println(commit)
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	//fmt.Println(buf)
	//fmt.Println(public.Commit().MarshalBinary())
	//if err = bls.Verify(suite, public.Commit(), msg, buf); err != nil {
	//	panic("tbls: math is wrong!")
	//}
	return sig, nil
}
