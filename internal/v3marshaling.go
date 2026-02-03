package internal

import (
	"reflect"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/internal/protobuf"
	"go.dedis.ch/kyber/v4/share"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// CompatiblePriShare is a struct for PriShare used when marshaling to
// ensure compatibility with V3
type CompatiblePriShare struct {
	I int64
	V kyber.Scalar
}

func MarshalPriShare(priShare *share.PriShare) ([]byte, error) {
	toEncode := &CompatiblePriShare{
		I: int64(priShare.I),
		V: priShare.V,
	}
	return protobuf.Encode(toEncode)
}

func UnmarshalPriShare(data []byte, suite Suite) (*share.PriShare, error) {
	compatiblePriShare := &CompatiblePriShare{}
	constructors := make(protobuf.Constructors)
	var secret kyber.Scalar
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Scalar() }
	err := protobuf.DecodeWithConstructors(data, compatiblePriShare, constructors)
	if err != nil {
		return nil, err
	}
	priShare := &share.PriShare{
		I: uint32(compatiblePriShare.I),
		V: compatiblePriShare.V,
	}
	return priShare, nil
}

// PedersenCompatibleDeal is a struct for Deal used when marshaling
// to ensure compatibility with Kyber V3.
type PedersenCompatibleDeal struct {
	SessionID   []byte
	SecShare    []byte
	T           uint32
	Commitments []kyber.Point
}

func MarshalPedersenDeal(deal *vss.Deal) ([]byte, error) {
	secShareBytes, err := MarshalPriShare(deal.SecShare)
	if err != nil {
		return nil, err
	}
	compatibleDeal := &PedersenCompatibleDeal{
		SessionID:   deal.SessionID,
		SecShare:    secShareBytes,
		T:           deal.T,
		Commitments: deal.Commitments,
	}
	return protobuf.Encode(compatibleDeal)
}

func UnmarshalPedersenDeal(data []byte, suite Suite) (*vss.Deal, error) {
	compatibleDeal := &PedersenCompatibleDeal{}
	constructors := make(protobuf.Constructors)
	var point kyber.Point
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	err := protobuf.DecodeWithConstructors(data, compatibleDeal, constructors)
	if err != nil {
		return nil, err
	}
	secShare, err := UnmarshalPriShare(compatibleDeal.SecShare, suite)
	if err != nil {
		return nil, err
	}
	deal := &vss.Deal{
		SessionID:   compatibleDeal.SessionID,
		T:           compatibleDeal.T,
		SecShare:    secShare,
		Commitments: compatibleDeal.Commitments,
	}
	return deal, nil
}
