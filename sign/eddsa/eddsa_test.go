package eddsa

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"os"
	"strings"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EdDSATestVectors taken from RFC8032 section 7.1
var EdDSATestVectors = []struct {
	private   string
	public    string
	message   string
	signature string
}{
	{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
	{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		"72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	{"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		"af82",
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	{"f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
		"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
		"08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
		"0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"},
	{"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"},
}

// Tests if marshalling and unmarshalling an EdDSA signature gives us the same
// signature
func TestEdDSAMarshalling(t *testing.T) {
	for _, vec := range EdDSATestVectors {
		seed, err := hex.DecodeString(vec.private)
		assert.Nil(t, err)

		stream := ConstantStream(seed)
		edDSA := NewEdDSA(stream)

		assert.Equal(t, edDSA.Public.String(), vec.public)

		marshalled, err := edDSA.MarshalBinary()
		assert.Nil(t, err)
		assert.NotNil(t, marshalled)

		unmarshalled := &EdDSA{}
		err = unmarshalled.UnmarshalBinary(marshalled)
		assert.Nil(t, err)
		assert.Equal(t, edDSA, unmarshalled)
	}
}

// Comparing our implementation with the test vectors of the RFC
func TestEdDSASigning(t *testing.T) {
	for i, vec := range EdDSATestVectors {
		seed, err := hex.DecodeString(vec.private)
		assert.Nil(t, err)
		if len(vec.private) != 64 || len(seed) != 32 {
			t.Fatal("len vec.private")
		}

		stream := ConstantStream(seed)

		ed := NewEdDSA(stream)

		data, _ := ed.Public.MarshalBinary()
		if hex.EncodeToString(data) != vec.public {
			t.Error("Public not equal")
		}
		if len(vec.public) != 64 {
			t.Fatal("len vec.private")
		}

		msg, _ := hex.DecodeString(vec.message)

		sig, err := ed.Sign(msg)
		assert.Nil(t, err)

		if hex.EncodeToString(sig) != vec.signature {
			t.Error("Test", i, "Signature wrong", hex.EncodeToString(sig), vec.signature)
		}
		assert.Nil(t, Verify(ed.Public, msg, sig))
	}
}

// Test signature malleability
func TestEdDSAVerifyMalleability(t *testing.T) {
	/* l = 2^252+27742317777372353535851937790883648493, prime order of the base point */
	var L []uint16 = []uint16{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
		0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	var c uint16 = 0

	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomStream := suite.RandomStream()
	ed := NewEdDSA(randomStream)

	msg := random.Bits(256, true, randomStream)

	sig, err := ed.Sign(msg)
	require.Nil(t, err)
	require.Nil(t, Verify(ed.Public, msg, sig))

	// Add l to signature
	for i := 0; i < 32; i++ {
		c += uint16(sig[32+i]) + L[i]
		sig[32+i] = byte(c)
		c >>= 8
	}

	err = Verify(ed.Public, msg, sig)
	require.EqualError(t, err, "signature is not canonical")

	// Additional malleability test from golang/crypto
	// https://github.com/golang/crypto/blob/master/ed25519/ed25519_test.go#L167
	msg2 := []byte{0x54, 0x65, 0x73, 0x74}
	sig2 := []byte{
		0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a,
		0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b,
		0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67,
		0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33,
		0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
	}
	publicKey := []byte{
		0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5,
		0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34,
		0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa}

	err = VerifyWithChecks(publicKey, msg2, sig2)
	require.EqualError(t, err, "signature is not canonical")
}

// Test non-canonical R
func TestEdDSAVerifyNonCanonicalR(t *testing.T) {
	var nonCanonicalR []byte = []byte{0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomStream := suite.RandomStream()
	ed := NewEdDSA(randomStream)

	msg := random.Bits(256, true, randomStream)

	sig, err := ed.Sign(msg)
	require.Nil(t, err)
	require.Nil(t, Verify(ed.Public, msg, sig))

	for i := 0; i < 32; i++ {
		sig[i] = nonCanonicalR[i]
	}
	err = Verify(ed.Public, msg, sig)
	require.EqualError(t, err, "R is not canonical")
}

// Test non-canonical keys
func TestEdDSAVerifyNonCanonicalPK(t *testing.T) {
	var nonCanonicalPk []byte = []byte{0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomStream := suite.RandomStream()
	ed := NewEdDSA(randomStream)

	msg := random.Bits(256, true, randomStream)

	sig, err := ed.Sign(msg)
	require.Nil(t, err)
	require.Nil(t, Verify(ed.Public, msg, sig))

	err = VerifyWithChecks(nonCanonicalPk, msg, sig)
	require.EqualError(t, err, "public key is not canonical")
}

// Test for small order R
func TestEdDSAVerifySmallOrderR(t *testing.T) {
	var smallOrderR []byte = []byte{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
		0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
		0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomStream := suite.RandomStream()
	ed := NewEdDSA(randomStream)

	msg := random.Bits(256, true, randomStream)

	sig, err := ed.Sign(msg)
	require.Nil(t, err)
	require.Nil(t, Verify(ed.Public, msg, sig))

	for i := 0; i < 32; i++ {
		sig[i] = smallOrderR[i]
	}

	err = Verify(ed.Public, msg, sig)
	require.EqualError(t, err, "R has small order")
}

// Test for small order public key
func TestEdDSAVerifySmallOrderPK(t *testing.T) {
	var smallOrderPk []byte = []byte{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
		0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
		0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomStream := suite.RandomStream()
	ed := NewEdDSA(randomStream)

	msg := random.Bits(256, true, randomStream)

	sig, err := ed.Sign(msg)
	require.Nil(t, err)
	require.Nil(t, Verify(ed.Public, msg, sig))

	err = ed.Public.UnmarshalBinary(smallOrderPk)
	require.Nil(t, err)

	err = Verify(ed.Public, msg, sig)
	require.EqualError(t, err, "public key has small order")
}

// Test the property of a EdDSA signature
func TestEdDSASigningRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow tests in -short mode")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()

	for i := 0.0; i < 10000; i++ {
		ed := NewEdDSA(suite.RandomStream())

		msg := make([]byte, 32)
		_, err := rand.Read(msg)
		assert.NoError(t, err)

		sig, err := ed.Sign(msg)
		assert.Nil(t, err)
		// see https://tools.ietf.org/html/rfc8032#section-5.1.6 (item 6.)
		assert.Equal(t, uint8(0), sig[63]&0xe0)
		assert.Nil(t, Verify(ed.Public, msg, sig))
	}
}

type constantStream struct {
	seed []byte
}

// ConstantStream is a cipher.Stream which always returns
// the same value.
func ConstantStream(buff []byte) cipher.Stream {
	return &constantStream{buff}
}

// XORKexStream implements the cipher.Stream interface
func (cs *constantStream) XORKeyStream(dst, src []byte) {
	copy(dst, cs.seed)
}

// Adapted from golang.org/x/crypto/ed25519.
func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test cases from
	// https://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("testdata/sign.input.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	scanner := bufio.NewScanner(testData)
	lineNo := 0

	const SignatureSize = 64
	const PublicKeySize = 32
	const PrivateKeySize = 32

	for scanner.Scan() {
		lineNo++

		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			t.Fatalf("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKey, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:SignatureSize]

		if l := len(pubKey); l != PublicKeySize {
			t.Fatalf("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKey)

		stream := ConstantStream(privBytes)
		ed := NewEdDSA(stream)

		data, _ := ed.Public.MarshalBinary()
		if !bytes.Equal(data, pubKey) {
			t.Error("Public not equal")
		}

		sig2, err := ed.Sign(msg)
		assert.Nil(t, err)

		if !bytes.Equal(sig, sig2[:]) {
			t.Errorf("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		assert.Nil(t, Verify(ed.Public, msg, sig2))
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("error reading test data: %s", err)
	}
}
