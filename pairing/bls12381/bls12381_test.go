package bls12381

import (
	"crypto/rand"
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	circl "go.dedis.ch/kyber/v3/pairing/bls12381/circl"
	kilic "go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

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
