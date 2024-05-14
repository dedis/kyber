package bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	circl "go.dedis.ch/kyber/v3/pairing/bls12381/circl"
	kilic "go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
	"gopkg.in/yaml.v3"
)

var (
	deserializationG1Tests, _ = filepath.Abs("pairing/bls12381/deserialization_tests/G1/*")
	deserializationG2Tests, _ = filepath.Abs("pairing/bls12381/deserialization_tests/G2/*")
)

func TestScalarEndianess(t *testing.T) {
	suites := []pairing.Suite{
		kilic.NewBLS12381Suite(),
		circl.NewSuiteBLS12381(),
	}

	seed := "TestScalarEndianess"
	rng := blake2xb.New([]byte(seed))

	// byte 1 and 8
	var one, eight byte
	one |= 1
	eight |= 8

	for _, suite := range suites {
		// Select a random element
		s := suite.G1().Scalar().Pick(rng)
		sInv := s.Clone().Inv(s)

		// We expect the multiplicative neutral 1
		neutral := s.Mul(s, sInv)
		byteNeutral, err := neutral.MarshalBinary()
		require.NoError(t, err)

		if neutral.ByteOrder() == kyber.LittleEndian {
			require.Equal(t, byteNeutral[0], eight)
		} else {
			require.Equal(t, byteNeutral[len(byteNeutral)-1], one)
		}
	}
}

func TestZKCryptoVectorsG1Compressed(t *testing.T) {
	type Test struct {
		Input struct {
			PubKeyHexStr string `yaml:"pubkey"`
		}
		IsValidPredicate *bool `yaml:"output"`
	}
	tests, err := filepath.Glob(deserializationG1Tests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.IsValidPredicate != nil
			byts, err := hex.DecodeString(test.Input.PubKeyHexStr)
			if err != nil && testCaseValid {
				panic(err)
			}

			// Test kilic
			g := kilic.NullG1()
			err = g.UnmarshalBinary(byts)
			if err == nil && !testCaseValid {
				panic("err should not be nil")
			}
			if err != nil && testCaseValid {
				panic("err should be nil")
			}

			// Test circl
			g2 := circl.G1Elt{}
			err = g2.UnmarshalBinary(byts)
			if err == nil && !testCaseValid {
				panic("err should not be nil")
			}
			if err != nil && testCaseValid {
				panic("err should be nil")
			}
		})
	}
}

func TestZKCryptoVectorsG2Compressed(t *testing.T) {
	type Test struct {
		Input struct {
			SignatureHexStr string `yaml:"signature"`
		}
		IsValidPredicate *bool `yaml:"output"`
	}
	tests, err := filepath.Glob(deserializationG2Tests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.IsValidPredicate != nil
			byts, err := hex.DecodeString(test.Input.SignatureHexStr)
			if err != nil && testCaseValid {
				panic(err)
			}

			// Test kilic
			g := kilic.NullG2()
			err = g.UnmarshalBinary(byts)
			if err == nil && !testCaseValid {
				panic("err should not be nil")
			}
			if err != nil && testCaseValid {
				panic("err should be nil")
			}

			// Test circl
			g2 := circl.G2Elt{}
			err = g2.UnmarshalBinary(byts)
			if err == nil && !testCaseValid {
				panic("err should not be nil")
			}
			if err != nil && testCaseValid {
				panic("err should be nil")
			}
		})
	}
}

var (
	dataSize     = 32
	numSigs      = []int{1, 10, 100, 1000, 10000}
	curveOptions = []string{"kilic", "circl"}
)

// Used to avoid compiler optimizations
// https://www.practical-go-lessons.com/chap-34-benchmarks#:~:text=This%20variable%20is%20just%20here%20to%20avoid%20compiler%20optimization
var result interface{}

func BenchmarkKilic(b *testing.B) {
	BLSBenchmark(b, "kilic")
}

func BenchmarkCircl(b *testing.B) {
	BLSBenchmark(b, "circl")
}

func BLSBenchmark(b *testing.B, curveOption string) {
	b.Logf("----------------------")
	b.Logf("Payload to sign: %d bytes\n", dataSize)
	b.Logf("Numbers of signatures: %v\n", numSigs)
	b.Logf("Curve options: %v\n", curveOptions)
	b.Logf("----------------------")

	// Initialize all variables.
	msgData := make([]byte, dataSize)
	nBytes, err := rand.Read(msgData)
	if err != nil {
		panic(err)
	}
	if nBytes != dataSize {
		panic(fmt.Errorf("only read %d random bytes, but data size is %d", nBytes, dataSize))
	}

	randSource := random.New(rand.Reader)
	var suite pairing.Suite
	if curveOption == "kilic" {
		suite = kilic.NewBLS12381Suite()
	} else if curveOption == "circl" {
		suite = circl.NewSuiteBLS12381()
	} else {
		panic(fmt.Errorf("invalid curve option: %s", curveOption))
	}

	schemeOnG1 := bls.NewSchemeOnG1(suite)
	schemeOnG2 := bls.NewSchemeOnG2(suite)

	maxN := 1
	for _, s := range numSigs {
		if maxN < s {
			maxN = s
		}
	}

	privKeysOnG1 := make([]kyber.Scalar, maxN)
	privKeysOnG2 := make([]kyber.Scalar, maxN)
	pubKeysOnG1 := make([]kyber.Point, maxN)
	pubKeysOnG2 := make([]kyber.Point, maxN)
	sigsOnG1 := make([][]byte, maxN)
	sigsOnG2 := make([][]byte, maxN)

	for i := 0; i < maxN; i++ {
		privKeysOnG1[i], pubKeysOnG1[i] = schemeOnG1.NewKeyPair(randSource)
		sigsOnG1[i], err = schemeOnG1.Sign(privKeysOnG1[i], msgData)
		if err != nil {
			panic(err)
		}
		privKeysOnG2[i], pubKeysOnG2[i] = schemeOnG2.NewKeyPair(randSource)
		sigsOnG2[i], err = schemeOnG2.Sign(privKeysOnG2[i], msgData)
		if err != nil {
			panic(err)
		}
	}

	for _, n := range numSigs {
		// Benchmark aggregation of public keys
		b.Run(fmt.Sprintf("AggregatePublicKeys-G1 on %d signs", n), func(bb *testing.B) {
			for j := 0; j < bb.N; j++ {
				result = schemeOnG1.AggregatePublicKeys(pubKeysOnG1[:n]...)
			}
		})
		b.Run(fmt.Sprintf("AggregatePublicKeys-G2 on %d signs", n), func(bb *testing.B) {
			for j := 0; j < bb.N; j++ {
				result = schemeOnG2.AggregatePublicKeys(pubKeysOnG2[:n]...)
			}
		})

		// Benchmark aggregation of signatures
		b.Run(fmt.Sprintf("AggregateSign-G1 on %d signs", n), func(bb *testing.B) {
			for j := 0; j < bb.N; j++ {
				result, err = schemeOnG1.AggregateSignatures(sigsOnG1[:n]...)
				if err != nil {
					panic(err)
				}
			}
		})
		b.Run(fmt.Sprintf("AggregateSign-G1 on %d signs", n), func(bb *testing.B) {
			for j := 0; j < bb.N; j++ {
				result, err = schemeOnG2.AggregateSignatures(sigsOnG2[:n]...)
				if err != nil {
					panic(err)
				}
			}
		})
	}

	// Benchmark keygen
	b.Run("KeyGen-G1", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			result, _ = schemeOnG1.NewKeyPair(randSource)
		}
	})
	b.Run("KeyGen-G2", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			result, _ = schemeOnG2.NewKeyPair(randSource)
		}
	})

	// Benchmark sign
	b.Run("Sign-G1", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			result, err = schemeOnG1.Sign(privKeysOnG1[0], msgData)
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("Sign-G2", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			result, err = schemeOnG2.Sign(privKeysOnG2[0], msgData)
			if err != nil {
				panic(err)
			}
		}
	})

	// Benchmark verify
	b.Run("Verify-G1", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			err = schemeOnG1.Verify(pubKeysOnG1[0], msgData, sigsOnG1[0])
			if err != nil {
				panic(err)
			}
		}
	})
	b.Run("Verify-G2", func(bb *testing.B) {
		for j := 0; j < bb.N; j++ {
			err = schemeOnG2.Verify(pubKeysOnG2[0], msgData, sigsOnG2[0])
			if err != nil {
				panic(err)
			}
		}
	})
}
