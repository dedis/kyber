package vss

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	pedersenv3 "go.dedis.ch/kyber/v3/share/vss/pedersen"
	"go.dedis.ch/kyber/v4/share/vss/pedersen/proto"
	"go.dedis.ch/protobuf"

	suitev3 "go.dedis.ch/kyber/v3/group/edwards25519"
	suitev4 "go.dedis.ch/kyber/v4/group/edwards25519"

	kyberV3 "go.dedis.ch/kyber/v3"
	kyberV4 "go.dedis.ch/kyber/v4"

	pb "google.golang.org/protobuf/proto"
)

var (
	suiteV3 = suitev3.NewBlakeSHA256Ed25519()
	suiteV4 = suitev4.NewBlakeSHA256Ed25519()
)

type VersionlessVerifier interface {
	getVersion() int
	getIndex() int
	processEncryptedDeal([]byte) ([]byte, error)
	processResponse([]byte) error
	dealCertified() bool
	deal() ([]byte, error)
}

type VersionlessDealer interface {
	getVersion() int
	encryptedDeals() ([][]byte, error)
	processResponse([]byte) ([]byte, error)
}

type VerifierV3 struct {
	useProtobuf bool
	*pedersenv3.Verifier
	index int
}

func (v *VerifierV3) getVersion() int {
	return 3
}

func newVerifierV3(index int, secretKey kyberV3.Scalar, useProtobuf bool,
	dealerPub kyberV3.Point, publicKeys []kyberV3.Point) *VerifierV3 {
	verifier, err := pedersenv3.NewVerifier(suiteV3, secretKey, dealerPub, publicKeys)
	if err != nil {
		panic(err)
	}
	return &VerifierV3{
		useProtobuf: useProtobuf,
		Verifier:    verifier,
		index:       index,
	}
}

func (v *VerifierV3) getIndex() int {
	return v.index
}

func (v *VerifierV3) processEncryptedDeal(dealBytes []byte) ([]byte, error) {
	switch v.useProtobuf {
	case true:
		dealProto := &V3EncryptedDeal{}
		constructors := make(protobuf.Constructors)
		var point kyberV3.Point
		var scalar kyberV3.Scalar
		constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV3.Point() }
		constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV3.Scalar() }
		err := protobuf.DecodeWithConstructors(dealBytes, dealProto, constructors)
		if err != nil {
			return nil, err
		}
		deal := dealProto.ToV3EncryptedDeal()
		resp, err := v.ProcessEncryptedDeal(deal)
		if err != nil {
			return nil, err
		}
		return protobuf.Encode(resp)
	case false:
		dealProto, err := unmarshallV3EncryptedDealProto(dealBytes)
		if err != nil {
			return nil, err
		}
		dealV3 := protoV3EncryptedDealToV3EncryptedDeal(dealProto)
		resp, err := v.ProcessEncryptedDeal(dealV3)
		if err != nil {
			return nil, err
		}
		return protobuf.Encode(resp)
	default:
		return nil, errors.New("unsupported encrypted deal type")
	}
}

func (v *VerifierV3) processResponse(responseBytes []byte) error {
	if responseBytes == nil {
		return v.ProcessResponse(nil)
	}
	response := &pedersenv3.Response{}
	constructors := make(protobuf.Constructors)
	var point kyberV3.Point
	var scalar kyberV3.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV3.Point() }
	constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV3.Scalar() }
	err := protobuf.DecodeWithConstructors(responseBytes, response, constructors)
	if err != nil {
		return err
	}

	// Skip if the response is our own
	if response.Index == uint32(v.index) {
		return nil
	}

	return v.ProcessResponse(response)
}

func (v *VerifierV3) dealCertified() bool {
	return v.DealCertified()
}

func (v *VerifierV3) deal() ([]byte, error) {
	dealt := v.Deal()
	return protobuf.Encode(dealt)
}

type VerifierV4 struct {
	useProtobuf bool
	*Verifier
	index int
}

func (v *VerifierV4) getVersion() int {
	return 4
}

func newVerifierV4(index int, secretKey kyberV4.Scalar, useProtobuf bool,
	dealerPub kyberV4.Point, publicKeys []kyberV4.Point) *VerifierV4 {
	verifier, _ := NewVerifier(suiteV4, secretKey, dealerPub, publicKeys)
	return &VerifierV4{
		useProtobuf: useProtobuf,
		Verifier:    verifier,
		index:       index,
	}
}

func (v *VerifierV4) getIndex() int {
	return v.index
}

func (v *VerifierV4) processEncryptedDeal(dealBytes []byte) ([]byte, error) {
	switch v.useProtobuf {
	case true:
		dealV4Fix := &V4EncryptedDeal{}
		constructors := make(protobuf.Constructors)
		var point kyberV4.Point
		var scalar kyberV4.Scalar
		constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV4.Point() }
		constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV4.Scalar() }
		err := protobuf.DecodeWithConstructors(dealBytes, dealV4Fix, constructors)
		if err != nil {
			return nil, err
		}
		dealV4 := dealV4Fix.ToV4EncryptedDeal()
		resp, err := v.ProcessEncryptedDeal(dealV4)
		if err != nil {
			return nil, err
		}
		return protobuf.Encode(resp)
	case false:
		dealProto, err := unmarshallV4EncryptedDealProto(dealBytes)
		if err != nil {
			return nil, err
		}
		dealV4 := protoEncryptedDealToV4EncryptedDeal(dealProto)
		resp, err := v.ProcessEncryptedDeal(dealV4)
		if err != nil {
			return nil, err
		}
		return protobuf.Encode(resp)
	default:
		return nil, errors.New("invalid useProtobuf")
	}
}

func (v *VerifierV4) processResponse(responseBytes []byte) error {
	if responseBytes == nil {
		return v.ProcessResponse(nil)
	}
	response := &Response{}
	constructors := make(protobuf.Constructors)
	var point kyberV4.Point
	var scalar kyberV4.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV4.Point() }
	constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV4.Scalar() }
	err := protobuf.DecodeWithConstructors(responseBytes, response, constructors)
	if err != nil {
		return err
	}

	// Skip if the response is our own
	if response.Index == uint32(v.index) {
		return nil
	}

	return v.ProcessResponse(response)
}

func (v *VerifierV4) dealCertified() bool {
	return v.DealCertified()
}

func (v *VerifierV4) deal() ([]byte, error) {
	dealt := v.Deal()
	return protobuf.Encode(dealt)
}

type DealerV3 struct {
	useProtobuf bool
	*pedersenv3.Dealer
}

func (d *DealerV3) getVersion() int {
	return 3
}

func (d *DealerV3) encryptedDeals() ([][]byte, error) {
	deals, err := d.EncryptedDeals()
	if err != nil {
		return nil, err
	}
	return encryptedDealsV3ToBytes(deals, d.useProtobuf)
}

func (d *DealerV3) processResponse(responseBytes []byte) ([]byte, error) {
	response := &pedersenv3.Response{}
	constructors := make(protobuf.Constructors)
	var point kyberV3.Point
	var scalar kyberV3.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV3.Point() }
	constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV3.Scalar() }
	err := protobuf.DecodeWithConstructors(responseBytes, response, constructors)
	if err != nil {
		return nil, err
	}
	justification, err := d.ProcessResponse(response)
	if err != nil {
		return nil, err
	}
	return protobuf.Encode(justification)
}

type DealerV4 struct {
	useProtobuf bool
	*Dealer
}

func (d *DealerV4) getVersion() int {
	return 4
}

func (d *DealerV4) encryptedDeals() ([][]byte, error) {
	deals, err := d.EncryptedDeals()
	if err != nil {
		return nil, err
	}
	return encryptedDealsV4ToBytes(deals, d.useProtobuf)
}

func (d *DealerV4) processResponse(responseBytes []byte) ([]byte, error) {
	response := &Response{}
	constructors := make(protobuf.Constructors)
	var point kyberV4.Point
	var scalar kyberV4.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV4.Point() }
	constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV4.Scalar() }
	err := protobuf.DecodeWithConstructors(responseBytes, response, constructors)
	if err != nil {
		return nil, err
	}
	justification, err := d.ProcessResponse(response)
	if err != nil {
		return nil, err
	}
	return protobuf.Encode(justification)
}

func genSecret(version int) []byte {
	switch version {
	case 3:
		secretV3, _ := genPairV3()
		secretBytes, err := secretV3.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return secretBytes
	case 4:
		secretV4, _ := genPairV4()
		secretBytes, err := secretV4.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return secretBytes
	default:
		panic("invalid version")
	}
}

func genPairV3() (kyberV3.Scalar, kyberV3.Point) {
	secret := suiteV3.Scalar().Pick(suiteV3.RandomStream())
	public := suiteV3.Point().Mul(secret, nil)
	return secret, public
}

func genPairV4() (kyberV4.Scalar, kyberV4.Point) {
	secret := suiteV4.Scalar().Pick(suiteV4.RandomStream())
	public := suiteV4.Point().Mul(secret, nil)
	return secret, public
}

func genDealerV3(publicKeys [][]byte, threshold int,
	secret kyberV3.Scalar, useProtobuf bool) (*DealerV3, kyberV3.Point, error) {
	// Read all public points using kyber V3
	verifiersPubV3 := getPubV3(publicKeys)
	dealerSecV3, dealerPubV3 := genPairV3()

	dealer, err := pedersenv3.NewDealer(suiteV3, dealerSecV3, secret, verifiersPubV3, threshold)
	if err != nil {
		return nil, nil, err
	}

	dealerV3 := &DealerV3{
		useProtobuf: useProtobuf,
		Dealer:      dealer,
	}

	return dealerV3, dealerPubV3, nil
}

func genDealerV4(publicKeys [][]byte, threshold uint32,
	secret kyberV4.Scalar, useProtobuf bool) (*DealerV4, kyberV4.Point, error) {
	// Read all public points using kyber V3
	verifiersPubV4 := getPubV4(publicKeys)
	dealerSecV4, dealerPubV3 := genPairV4()

	dealer, err := NewDealer(suiteV4, dealerSecV4, secret, verifiersPubV4, threshold)
	if err != nil {
		return nil, nil, err
	}
	dealerV4 := &DealerV4{Dealer: dealer, useProtobuf: useProtobuf}

	return dealerV4, dealerPubV3, nil
}

func bytesToPointV3(data []byte) kyberV3.Point {
	point := suiteV3.Point()
	err := point.UnmarshalBinary(data)
	if err != nil {
		panic(err)
	}
	return point
}

func bytesToPointV4(data []byte) kyberV4.Point {
	point := suiteV4.Point()
	err := point.UnmarshalBinary(data)
	if err != nil {
		panic(err)
	}
	return point
}

func bytesToScalarV3(data []byte) kyberV3.Scalar {
	point := suiteV3.Scalar()
	err := point.UnmarshalBinary(data)
	if err != nil {
		panic(err)
	}
	return point
}

func bytesToScalarV4(data []byte) kyberV4.Scalar {
	point := suiteV4.Scalar()
	err := point.UnmarshalBinary(data)
	if err != nil {
		panic(err)
	}
	return point
}

func genPubSecKeys(nbV3, nbV4 int) ([][]byte, [][]byte) {
	total := nbV3 + nbV4
	verifiersSecretKeys := make([][]byte, total)
	verifiersPublicKeys := make([][]byte, total)
	for i := 0; i < nbV3; i++ {
		verifierSec, verifierPub := genPairV3()

		pubBytes, err := verifierPub.MarshalBinary()
		if err != nil {
			panic(fmt.Errorf("failed to marshal verifier public key V3: %w", err))
		}
		verifiersPublicKeys[i] = pubBytes

		secBytes, err := verifierSec.MarshalBinary()
		if err != nil {
			panic(fmt.Errorf("failed to marshal verifier secret key V3: %w", err))
		}
		verifiersSecretKeys[i] = secBytes
	}

	for i := nbV3; i < nbV3+nbV4; i++ {
		verifierSec, verifierPub := genPairV4()

		pubBytes, err := verifierPub.MarshalBinary()
		if err != nil {
			panic(fmt.Errorf("failed to marshal verifier public key V4: %w", err))
		}
		verifiersPublicKeys[i] = pubBytes

		secBytes, err := verifierSec.MarshalBinary()
		if err != nil {
			panic(fmt.Errorf("failed to marshal verifier secret key V4: %w", err))
		}
		verifiersSecretKeys[i] = secBytes
	}
	return verifiersSecretKeys, verifiersPublicKeys
}

func getPubV3(publicKeys [][]byte) []kyberV3.Point {
	pubV3 := make([]kyberV3.Point, len(publicKeys))
	for i := 0; i < len(publicKeys); i++ {
		pubV3[i] = bytesToPointV3(publicKeys[i])
	}
	return pubV3
}

func getPubV4(publicKeys [][]byte) []kyberV4.Point {
	pubV3 := make([]kyberV4.Point, len(publicKeys))
	for i := 0; i < len(publicKeys); i++ {
		pubV3[i] = bytesToPointV4(publicKeys[i])
	}
	return pubV3
}

func genVerifiers(nbV3, nbV4 int, dealerPublicKey []byte, privateKeys,
	publicKeys [][]byte, useProtobuf bool) []VersionlessVerifier {
	total := nbV3 + nbV4
	verifiers := make([]VersionlessVerifier, total)

	// Requires the verifiers' pub/sec to already been created (call genPubSecKeys)

	dealerPubV3 := bytesToPointV3(dealerPublicKey)
	dealerPubV4 := bytesToPointV4(dealerPublicKey)
	publicKeysV3 := getPubV3(publicKeys)
	publicKeysV4 := getPubV4(publicKeys)
	for i := 0; i < nbV3; i++ {
		verifierSecretKey := privateKeys[i]
		secretKeyV3 := bytesToScalarV3(verifierSecretKey)
		verifiers[i] = newVerifierV3(i, secretKeyV3, useProtobuf, dealerPubV3, publicKeysV3)
	}
	for i := nbV3; i < nbV3+nbV4; i++ {
		verifierSecretKey := privateKeys[i]
		secretKeyV4 := bytesToScalarV4(verifierSecretKey)
		verifiers[i] = newVerifierV4(i, secretKeyV4, useProtobuf, dealerPubV4, publicKeysV4)
	}
	return verifiers
}

func encryptedDealsV3ToBytes(deals []*pedersenv3.EncryptedDeal, useProtobuf bool) ([][]byte, error) {
	dealsBytes := make([][]byte, len(deals))
	for i, deal := range deals {
		var dealBytes []byte
		var err error
		switch useProtobuf {
		case true:
			dealV3Fix := toV3EncryptedDealFixed(deal)
			dealBytes, err = protobuf.Encode(dealV3Fix)
		case false:
			dealBytes, err = pb.Marshal(v3EncryptedDealToProtoV3(deal))
		}
		if err != nil {
			return nil, err
		}
		dealsBytes[i] = dealBytes
	}
	return dealsBytes, nil
}

func encryptedDealsV4ToBytes(deals []*EncryptedDeal, useProtobuf bool) ([][]byte, error) {
	dealsBytes := make([][]byte, len(deals))
	for i, deal := range deals {
		var dealBytes []byte
		var err error
		switch useProtobuf {
		case true:
			dealV4Fix := toV4EncryptedDealFixed(deal)
			dealBytes, err = protobuf.Encode(dealV4Fix)
		case false:
			dealBytes, err = pb.Marshal(v4EncryptedDealToProto(deal))
		}
		if err != nil {
			return nil, err
		}
		dealsBytes[i] = dealBytes
	}
	return dealsBytes, nil
}

func byteArrayToDealsV3(arr [][]byte) []*pedersenv3.Deal {
	dealsV3 := make([]*pedersenv3.Deal, len(arr))
	for i, deal := range arr {
		dealV3 := &pedersenv3.Deal{}
		constructors := make(protobuf.Constructors)
		var point kyberV3.Point
		var scalar kyberV3.Scalar
		constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV3.Point() }
		constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV3.Scalar() }
		err := protobuf.DecodeWithConstructors(deal, dealV3, constructors)
		if err != nil {
			panic(fmt.Errorf("failed to unmarshal deal to V3: %w", err))
		}
		dealsV3[i] = dealV3
	}
	return dealsV3
}

func byteArrayToDealsV4(arr [][]byte) []*Deal {
	dealsV4 := make([]*Deal, len(arr))
	for i, deal := range arr {
		dealV4 := &Deal{}
		constructors := make(protobuf.Constructors)
		var point kyberV4.Point
		var scalar kyberV4.Scalar
		constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suiteV4.Point() }
		constructors[reflect.TypeOf(&scalar).Elem()] = func() interface{} { return suiteV4.Scalar() }
		err := protobuf.DecodeWithConstructors(deal, dealV4, constructors)
		if err != nil {
			panic(fmt.Errorf("failed to unmarshal deal to V4: %w", err))
		}
		dealsV4[i] = dealV4
	}
	return dealsV4
}

func dispatchDeals(t *testing.T, deals [][]byte, verifiers []VersionlessVerifier) [][]byte {
	responses := make([][]byte, len(deals))
	for i, deal := range deals {
		verifier := verifiers[i]
		err := verifier.processResponse(nil)
		if !errors.Is(err, pedersenv3.ErrNoDealBeforeResponse) && !errors.Is(err, ErrNoDealBeforeResponse) {
			t.Fatalf("Processing response before receiving a deal should cause an error")
		}
		resp, err := verifier.processEncryptedDeal(deal)
		require.NoError(t, err, "failed to process deal in version %i", verifier.getVersion())

		responses[i] = resp
	}
	return responses
}

func dispatchResponses(t *testing.T, responses [][]byte, verifiers []VersionlessVerifier) {
	for _, resp := range responses {
		for _, verifier := range verifiers {
			require.Nil(t, verifier.processResponse(resp))
		}
	}
}

func checkCertified(t *testing.T, verifiers []VersionlessVerifier) {
	for _, verifier := range verifiers {
		require.True(t, verifier.dealCertified())
	}
}

func collectDeals(t *testing.T, verifiers []VersionlessVerifier) [][]byte {
	deals := make([][]byte, len(verifiers))
	for i, v := range verifiers {
		deal, err := v.deal()
		require.NoError(t, err)
		deals[i] = deal
	}
	return deals
}

func runTest(t *testing.T, nbVerifiersV3, nbVerifiersV4, dealerVersion int, useProtobuf bool) {
	nbVerifiers := nbVerifiersV3 + nbVerifiersV4
	var threshold int
	switch dealerVersion {
	case 3:
		threshold = pedersenv3.MinimumT(nbVerifiers)
	case 4:
		threshold = int(MinimumT(uint32(nbVerifiers)))
	}
	// Generate all the public/secret keys
	privateKeys, publicKeys := genPubSecKeys(nbVerifiersV3, nbVerifiersV4)

	// Generate the secret
	secretBytes := genSecret(dealerVersion)

	var dealerPublicKey []byte
	var dealer VersionlessDealer
	// Create the dealer
	switch dealerVersion {
	case 3:
		secretV3 := bytesToScalarV3(secretBytes)
		dealerV3, dealerV3Pub, err := genDealerV3(publicKeys, threshold, secretV3, useProtobuf)
		dealer = dealerV3
		require.NoError(t, err)
		dealerPublicKey, err = dealerV3Pub.MarshalBinary()
		require.NoError(t, err)
	case 4:
		secretV4 := bytesToScalarV4(secretBytes)
		dealerV4, dealerV4Pub, err := genDealerV4(publicKeys, uint32(threshold), secretV4, useProtobuf)
		dealer = dealerV4
		require.NoError(t, err)
		dealerPublicKey, err = dealerV4Pub.MarshalBinary()
		require.NoError(t, err)
	}

	verifiers := genVerifiers(nbVerifiersV3, nbVerifiersV4, dealerPublicKey, privateKeys, publicKeys, useProtobuf)

	// 1. dispatch deal
	deals, err := dealer.encryptedDeals()
	require.NoError(t, err)
	responses := dispatchDeals(t, deals, verifiers)

	// 2. dispatch responses
	dispatchResponses(t, responses, verifiers)

	// 3. check certified
	checkCertified(t, verifiers)

	// 4. collect deals
	collectedDeals := collectDeals(t, verifiers)

	// 5. recover
	switch dealerVersion {
	case 3:
		collectedDealsV3 := byteArrayToDealsV3(collectedDeals)
		sec, err := pedersenv3.RecoverSecret(suiteV3, collectedDealsV3, nbVerifiers, pedersenv3.MinimumT(nbVerifiers))
		require.NoError(t, err)
		require.NotNil(t, sec)
	case 4:
		collectedDealsV4 := byteArrayToDealsV4(collectedDeals)
		sec, err := RecoverSecret(suiteV4, collectedDealsV4,
			uint32(nbVerifiers), MinimumT(uint32(nbVerifiers)))
		require.NoError(t, err)
		require.NotNil(t, sec)

	}

	switch dealerVersion {
	case 3:
		secretV3 := bytesToScalarV3(secretBytes)
		dealerV3, ok := dealer.(*DealerV3)
		require.True(t, ok)
		priPoly := dealerV3.PrivatePoly()
		priCoefficients := priPoly.Coefficients()
		require.Equal(t, secretV3.String(), priCoefficients[0].String())
	case 4:
		secretV4 := bytesToScalarV4(secretBytes)
		dealerV4, ok := dealer.(*DealerV4)
		require.True(t, ok)
		priPoly := dealerV4.PrivatePoly()
		priCoefficients := priPoly.Coefficients()
		require.Equal(t, secretV4.String(), priCoefficients[0].String())
	}
}

func TestVSS(t *testing.T) {
	tests := []struct {
		name          string
		nbV3          int
		nbV4          int
		dealerVersion int
		useProtobuf   bool
	}{
		{"V3Verifiers_V3Dealer_Protobuf", 7, 0, 3, true},
		{"V3Verifiers_V4Dealer_Protobuf", 7, 0, 4, true},
		{"V3Verifiers_V3Dealer_Proto", 7, 0, 3, false},
		{"V3Verifiers_V4Dealer_Proto", 7, 0, 4, false},
		{"V4Verifiers_V3Dealer_Protobuf", 0, 7, 3, true},
		{"V4Verifiers_V4Dealer_Protobuf", 0, 7, 4, true},
		{"V4Verifiers_V3Dealer_Proto", 0, 7, 3, false},
		{"V4Verifiers_V4Dealer_Proto", 0, 7, 4, false},
		{"V3V4Verifiers_V3Dealer_Protobuf", 3, 4, 3, false},
		{"V3V4Verifiers_V4Dealer_Protobuf", 3, 4, 4, false},
		{"V3V4Verifiers_V3Dealer_Proto", 3, 4, 3, true},
		{"V3V4Verifiers_V4Dealer_Proto", 3, 4, 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runTest(t, tt.nbV3, tt.nbV4, tt.dealerVersion, tt.useProtobuf)
		})
	}
}

type V3EncryptedDeal struct {
	DHKey     []byte `protobuf:"1"`
	Signature []byte `protobuf:"2"`
	Nonce     []byte `protobuf:"3"`
	Cipher    []byte `protobuf:"4"`
}

func (v *V3EncryptedDeal) ToV3EncryptedDeal() *pedersenv3.EncryptedDeal {
	deal := &pedersenv3.EncryptedDeal{
		DHKey:     v.DHKey,
		Signature: v.Signature,
		Nonce:     v.Nonce,
		Cipher:    v.Cipher,
	}
	if deal.Nonce == nil {
		// Set to NonceSize (copy-pasted from gcm.go)
		deal.Nonce = make([]byte, 12)
	}
	return deal
}

func toV3EncryptedDealFixed(deal *pedersenv3.EncryptedDeal) *V3EncryptedDeal {
	return &V3EncryptedDeal{
		DHKey:     deal.DHKey,
		Signature: deal.Signature,
		Nonce:     deal.Nonce,
		Cipher:    deal.Cipher,
	}
}

type V4EncryptedDeal struct {
	DHKey     []byte
	Signature []byte
	Cipher    []byte `protobuf:"4"`
}

func (v *V4EncryptedDeal) ToV4EncryptedDeal() *EncryptedDeal {
	return &EncryptedDeal{
		DHKey:     v.DHKey,
		Signature: v.Signature,
		Cipher:    v.Cipher,
	}
}

func toV4EncryptedDealFixed(deal *EncryptedDeal) *V4EncryptedDeal {
	return &V4EncryptedDeal{
		DHKey:     deal.DHKey,
		Signature: deal.Signature,
		Cipher:    deal.Cipher,
	}
}

func TestEncryptedDeal_Serialization(t *testing.T) {
	nbV3 := 3
	nbV4 := 7
	nbVerifiers := nbV3 + nbV4
	threshold := pedersenv3.MinimumT(nbVerifiers)

	// Generate all the public/secret keys
	_, publicKeys := genPubSecKeys(nbV3, nbV4)

	var dealer VersionlessDealer

	// Create the dealer
	secret, _ := genPairV3()
	dealer, _, err := genDealerV3(publicKeys, threshold, secret, true)
	require.NoError(t, err)

	// 1. dispatch deal
	dealerV3, ok := dealer.(*DealerV3)
	require.True(t, ok)
	deals, err := dealerV3.EncryptedDeals()
	require.NoError(t, err)

	// Encode the deals to bytes
	dealsBytes := make([][]byte, len(deals))
	for i, deal := range deals {
		dealBytes, err := protobuf.Encode(deal)
		require.NoError(t, err)
		dealsBytes[i] = dealBytes
	}

	// Decode the deals to V3
	for i, deal := range dealsBytes {
		dealV3 := &pedersenv3.EncryptedDeal{}
		err := protobuf.Decode(deal, dealV3)
		require.NoError(t, err)
		dealOg := deals[i]
		require.Equal(t, dealOg.DHKey, dealV3.DHKey)
		require.Equal(t, dealOg.Nonce, dealV3.Nonce)
		require.Equal(t, dealOg.Cipher, dealV3.Cipher)
		require.Equal(t, dealOg.Signature, dealV3.Signature)
	}

	// Decode the deals to V4
	for i, deal := range dealsBytes {
		dealV4 := &V4EncryptedDeal{}
		err := protobuf.Decode(deal, dealV4)
		require.NoError(t, err)
		dealOg := deals[i]
		require.Equal(t, dealOg.DHKey, dealV4.DHKey)
		require.Equal(t, dealOg.Cipher, dealV4.Cipher)
		require.Equal(t, dealOg.Signature, dealV4.Signature)
	}

}

func unmarshallV4EncryptedDealProto(data []byte) (*proto.EncryptedDeal, error) {
	deal := &proto.EncryptedDeal{}
	err := pb.Unmarshal(data, deal)
	return deal, err
}

func unmarshallV3EncryptedDealProto(data []byte) (*proto.EncryptedDealV3, error) {
	deal := &proto.EncryptedDealV3{}
	err := pb.Unmarshal(data, deal)
	return deal, err

}

func protoEncryptedDealToV4EncryptedDeal(protoDeal *proto.EncryptedDeal) *EncryptedDeal {
	return &EncryptedDeal{
		DHKey:     protoDeal.Dhkey,
		Signature: protoDeal.Signature,
		Cipher:    protoDeal.Cipher,
	}
}

func protoV3EncryptedDealToV3EncryptedDeal(protoDeal *proto.EncryptedDealV3) *pedersenv3.EncryptedDeal {
	deal := &pedersenv3.EncryptedDeal{
		DHKey:     protoDeal.Dhkey,
		Signature: protoDeal.Signature,
		Nonce:     protoDeal.Nonce,
		Cipher:    protoDeal.Cipher,
	}
	if deal.Nonce == nil {
		deal.Nonce = make([]byte, 12)
	}
	return deal
}

func v4EncryptedDealToProto(deal *EncryptedDeal) *proto.EncryptedDeal {
	return &proto.EncryptedDeal{
		Dhkey:     deal.DHKey,
		Signature: deal.Signature,
		Cipher:    deal.Cipher,
	}
}

func v3EncryptedDealToProtoV3(deal *pedersenv3.EncryptedDeal) *proto.EncryptedDealV3 {
	return &proto.EncryptedDealV3{
		Dhkey:     deal.DHKey,
		Signature: deal.Signature,
		Nonce:     deal.Nonce,
		Cipher:    deal.Cipher,
	}
}
