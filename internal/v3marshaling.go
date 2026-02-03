package internal

import (
	"reflect"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/internal/protobuf"
	"go.dedis.ch/kyber/v4/share"
	pedersenvss "go.dedis.ch/kyber/v4/share/vss/pedersen"
	rabinvss "go.dedis.ch/kyber/v4/share/vss/rabin"
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

func MarshalPedersenDeal(deal *pedersenvss.Deal) ([]byte, error) {
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

func UnmarshalPedersenDeal(data []byte, suite Suite) (*pedersenvss.Deal, error) {
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
	deal := &pedersenvss.Deal{
		SessionID:   compatibleDeal.SessionID,
		T:           compatibleDeal.T,
		SecShare:    secShare,
		Commitments: compatibleDeal.Commitments,
	}
	return deal, nil
}

// RabinCompatibleDeal is a struct for Deal used when marshaling
// to ensure compatibility with Kyber V3.
type RabinCompatibleDeal struct {
	SessionID   []byte
	SecShare    []byte
	RndShare    []byte
	T           uint32
	Commitments []kyber.Point
}

func MarshalRabinDeal(deal *rabinvss.Deal) ([]byte, error) {
	secShareBytes, err := MarshalPriShare(deal.SecShare)
	if err != nil {
		return nil, err
	}
	rndShareBytes, err := MarshalPriShare(deal.RndShare)
	if err != nil {
		return nil, err
	}
	compatibleDeal := &RabinCompatibleDeal{
		SessionID:   deal.SessionID,
		SecShare:    secShareBytes,
		RndShare:    rndShareBytes,
		T:           deal.T,
		Commitments: deal.Commitments,
	}
	return protobuf.Encode(compatibleDeal)
}

func UnmarshalRabinDeal(data []byte, suite Suite) (*rabinvss.Deal, error) {
	compatibleDeal := &RabinCompatibleDeal{}
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

	rndShare, err := UnmarshalPriShare(compatibleDeal.RndShare, suite)
	if err != nil {
		return nil, err
	}
	return &rabinvss.Deal{
		SessionID:   compatibleDeal.SessionID,
		SecShare:    secShare,
		RndShare:    rndShare,
		T:           compatibleDeal.T,
		Commitments: compatibleDeal.Commitments,
	}, nil
}
