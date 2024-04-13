package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/test"
)

var (
	outputFile = "benchmarks.json"
	suites     = []kyber.Group{
		nist.NewBlakeSHA256P256(), nist.NewBlakeSHA256QR512(),
		bn256.NewSuiteG1(), bn256.NewSuiteG2(), bn256.NewSuiteGT(),
		pairing.NewSuiteBn256(),
		edwards25519.NewBlakeSHA256Ed25519()}
)

// BenchmarkGroup runs benchmarks for the given group and writes the results to a JSON file.
func BenchmarkGroup(name string, description string, gb *test.GroupBench) map[string]interface{} {
	fmt.Printf("Running benchmarks for %s...\n", name)
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

func main() {
	// Write results to JSON file
	results := make(map[string]map[string]map[string]interface{})
	results["groups"] = make(map[string]map[string]interface{})

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	for _, suite := range suites {
		groupBench := test.NewGroupBench(suite)
		result := BenchmarkGroup(suite.String(), "Description", groupBench)
		results["groups"][suite.String()] = result
	}

	if err := encoder.Encode(results); err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}
	fmt.Printf("Benchmark results written to %s\n", outputFile)
}
