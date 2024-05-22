package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/pairing/bn254"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/anon"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/test"
)

var (
	outputFile = "../docs/benchmark-app/src/data/data.json"
	suites     = []kyber.Group{
		nist.NewBlakeSHA256P256(), nist.NewBlakeSHA256QR512(),
		bn256.NewSuiteG1(),
		bn254.NewSuiteG1(),
		edwards25519.NewBlakeSHA256Ed25519()}
	signatures = []string{"anon", "bls"}
)

// BenchmarkGroup runs benchmarks for the given group and writes the results to a JSON file.
func benchmarkGroup(name string, description string, gb *test.GroupBench) map[string]interface{} {
	fmt.Printf("Running benchmarks for group %s...\n", name)
	results := make(map[string]map[string]testing.BenchmarkResult)

	// Scalar operations
	results["scalar"] = make(map[string]testing.BenchmarkResult)
	results["scalar"]["add"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarAdd(b.N)
	})
	results["scalar"]["sub"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarSub(b.N)
	})
	results["scalar"]["neg"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarNeg(b.N)
	})
	results["scalar"]["mul"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarMul(b.N)
	})
	results["scalar"]["div"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarDiv(b.N)
	})
	results["scalar"]["inv"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarInv(b.N)
	})
	results["scalar"]["pick"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarPick(b.N)
	})
	results["scalar"]["encode"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarEncode(b.N)
	})
	results["scalar"]["decode"] = testing.Benchmark(func(b *testing.B) {
		gb.ScalarDecode(b.N)
	})

	// Point operations
	results["point"] = make(map[string]testing.BenchmarkResult)
	results["point"]["add"] = testing.Benchmark(func(b *testing.B) {
		gb.PointAdd(b.N)
	})
	results["point"]["sub"] = testing.Benchmark(func(b *testing.B) {
		gb.PointSub(b.N)
	})
	results["point"]["neg"] = testing.Benchmark(func(b *testing.B) {
		gb.PointNeg(b.N)
	})
	results["point"]["mul"] = testing.Benchmark(func(b *testing.B) {
		gb.PointMul(b.N)
	})
	results["point"]["baseMul"] = testing.Benchmark(func(b *testing.B) {
		gb.PointBaseMul(b.N)
	})
	results["point"]["pick"] = testing.Benchmark(func(b *testing.B) {
		gb.PointPick(b.N)
	})
	results["point"]["encode"] = testing.Benchmark(func(b *testing.B) {
		gb.PointEncode(b.N)
	})
	results["point"]["decode"] = testing.Benchmark(func(b *testing.B) {
		gb.PointDecode(b.N)
	})

	result := map[string]interface{}{
		"group":       name,
		"description": description,
		"benchmarks":  results,
	}

	return result
}

// BenchmarkSign runs benchmarks for the some signature schemes.
func benchmarkSign(sigType string) map[string]interface{} {
	fmt.Printf("Running benchmarks for %s signature scheme...\n", sigType)
	results := make(map[string]map[string]testing.BenchmarkResult)
	results["keygen"] = make(map[string]testing.BenchmarkResult)
	results["sign"] = make(map[string]testing.BenchmarkResult)
	results["verify"] = make(map[string]testing.BenchmarkResult)

	benchMessage := []byte("Hello World!")
	keys := []int{1, 10, 100}

	if sigType == "anon" {
		// Generate keys
		for _, i := range keys {
			results["keygen"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				anon.BenchGenKeys(edwards25519.NewBlakeSHA256Ed25519(), i)
			})
		}
		benchPubEd25519, benchPriEd25519 := anon.BenchGenKeys(edwards25519.NewBlakeSHA256Ed25519(), keys[len(keys)-1])

		// Signing
		for _, i := range keys {
			results["sign"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				anon.BenchSign(edwards25519.NewBlakeSHA256Ed25519(), benchPubEd25519[:i], benchPriEd25519, b.N, benchMessage)
			})
		}

		// Verification
		for _, i := range keys {
			results["verify"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				anon.BenchVerify(edwards25519.NewBlakeSHA256Ed25519(), benchPubEd25519[:i],
					anon.BenchGenSig(edwards25519.NewBlakeSHA256Ed25519(), i, benchMessage, benchPubEd25519, benchPriEd25519),
					b.N, benchMessage)
			})
		}
	} else if sigType == "bls" {
		// Key generation
		for _, i := range keys {
			scheme := bls.NewSchemeOnG1(bn256.NewSuite())
			results["keygen"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				test.BenchCreateKeys(b, scheme, i)
			})
		}

		// Signing
		for _, i := range keys {
			results["sign"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				_, scheme, _, privates, _, _ := test.PrepareBLS(i)
				test.BenchSign(b, scheme, benchMessage, privates)
			})
		}

		// Verification
		for _, i := range keys {
			results["verify"][fmt.Sprintf("%d", i)] = testing.Benchmark(func(b *testing.B) {
				suite, scheme, publics, _, msgs, sigs := test.PrepareBLS(i)
				test.BLSBenchVerify(b, sigs, scheme, suite, publics, msgs)
			})
		}
	}

	result := map[string]interface{}{
		"name":        sigType,
		"description": "",
		"benchmarks":  results,
	}

	return result
}

func main() {
	// Write results to JSON file
	results := make(map[string]map[string]map[string]interface{})

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	// Run benchmarks for each group
	results["groups"] = make(map[string]map[string]interface{})
	for _, suite := range suites {
		groupBench := test.NewGroupBench(suite)
		result := benchmarkGroup(suite.String(), "Description", groupBench)
		results["groups"][suite.String()] = result
	}

	// Run benchmarks for signatures
	results["sign"] = make(map[string]map[string]interface{})
	for _, sigType := range signatures {
		result := benchmarkSign(sigType)
		results["sign"][sigType] = result
	}

	if err := encoder.Encode(results); err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}
	fmt.Printf("Benchmark results written to %s\n", outputFile)
}
