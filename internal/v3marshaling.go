package internal

import (
	"fmt"
	"math"
	"reflect"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/internal/protobuf"
	"go.dedis.ch/kyber/v4/share"
)

// Suite defines the capabilities required by the v3marshalling package.
type Suite interface {
	// Group is needed for Group.Scalar
	kyber.Group
}

// compatiblePriShare is a struct for PriShare used when marshaling to
// ensure compatibility with V3
type compatiblePriShare struct {
	I int64
	V kyber.Scalar
}

// MarshalPriShare marshals a share.PriShare into bytes or returns an error
// if the encoding did not work. Encoding is compatible with Kyber V3
func MarshalPriShare(priShare *share.PriShare) ([]byte, error) {
	toEncode := &compatiblePriShare{
		I: int64(priShare.I),
		V: priShare.V,
	}
	return protobuf.Encode(toEncode)
}

// UnmarshalPriShare unmarshals a share.PriShare from bytes or returns an error
// if the decoding did not work. Decoding is compatible with Kyber V3
func UnmarshalPriShare(data []byte, suite Suite) (*share.PriShare, error) {
	compatiblePriShare := &compatiblePriShare{}
	constructors := make(protobuf.Constructors)
	constructors[reflect.TypeFor[kyber.Scalar]()] = func() interface{} { return suite.Scalar() }
	err := protobuf.DecodeWithConstructors(data, compatiblePriShare, constructors)

	// Check for overflow on I
	if compatiblePriShare.I < 0 || compatiblePriShare.I > math.MaxUint32 {
		return nil, fmt.Errorf("cannot cast I as uint32 due to overflow")
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
