package internal

import (
	"fmt"
	"math"
	"reflect"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/internal/protobuf"
	"go.dedis.ch/kyber/v4/share"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// compatiblePriShare is a struct for PriShare used when marshaling to
// ensure compatibility with V3
type compatiblePriShare struct {
	I int64
	V kyber.Scalar
}

func MarshalPriShare(priShare *share.PriShare) ([]byte, error) {
	toEncode := &compatiblePriShare{
		I: int64(priShare.I),
		V: priShare.V,
	}
	return protobuf.Encode(toEncode)
}

func UnmarshalPriShare(data []byte, suite Suite) (*share.PriShare, error) {
	compatiblePriShare := &compatiblePriShare{}
	constructors := make(protobuf.Constructors)
	constructors[reflect.TypeFor[kyber.Scalar]()] = func() interface{} { return suite.Scalar() }
	err := protobuf.DecodeWithConstructors(data, compatiblePriShare, constructors)

	// Check for overflow on I
	if compatiblePriShare.I < 0 || compatiblePriShare.I > math.MaxUint32 {
		return nil, fmt.Errorf("cannot cast I as int64 to uint32 due to overflow")
	}

	if err != nil {
		return nil, err
	}
	priShare := &share.PriShare{
		I: uint32(compatiblePriShare.I),
		V: compatiblePriShare.V,
	}
	return priShare, nil
}
