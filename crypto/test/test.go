package main

import (
	"dissent/crypto"
	"dissent/crypto/openssl"
	"dissent/crypto/ed25519"
	"dissent/crypto/sodium"
	"dissent/crypto/shuffle"
)


func testSuite(s crypto.Suite) {
	crypto.TestSuite(s)	// Basic ciphersuite tests
	shuffle.TestShuffle(s)	// Neff's shuffle is a good torture test
}

func benchSuite(s crypto.Suite) {
	crypto.BenchSuite(s)
	shuffle.BenchShuffle(s)
}

func testSuites() {
	// Native Go suites
	testSuite(crypto.NewAES128SHA256QR512())
	//testSuite(crypto.NewAES128SHA256QR1024())
	testSuite(crypto.NewAES128SHA256P256())
	testSuite(crypto.NewAES128SHA256Ed25519())
	testSuite(ed25519.NewAES128SHA256Ed25519())

	// OpenSSL-based suites
	testSuite(openssl.NewAES128SHA256P256())
	testSuite(openssl.NewAES192SHA384P384())
	testSuite(openssl.NewAES256SHA512P521())
}

func benchSuites() {
	println("\nNative QR512 suite:")
	benchSuite(crypto.NewAES128SHA256QR512())

	println("\nNative P256 suite:")
	benchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL P256 suite:")
	benchSuite(openssl.NewAES128SHA256P256())

	//println("\nNaive Go Ed25519 suite:")
	//benchSuite(crypto.NewAES128SHA256Ed25519())

	println("\nOptimized Go Ed25519 suite:")
	benchSuite(ed25519.NewAES128SHA256Ed25519())

	println("\nSodium C Ed25519 suite:")
	benchSuite(sodium.NewAES128SHA256Ed25519())
}

func main() {
//	s := crypto.NewAES128SHA256P256()
//	s := crypto.NewAES128SHA256Ed25519()
//	s := openssl.NewAES128SHA256P256()
//	s := ed25519.NewAES128SHA256Ed25519()
//	shuffle.TestShuffle(s)
//	return

//	println("\nNative P256 suite:")
//	crypto.BenchSuite(openssl.NewAES128SHA256P256())
//	println("\nOptimized Ed25519 suite:")
//	crypto.BenchSuite(ed25519.NewAES128SHA256Ed25519())
//	println("\nSodium Ed25519 suite:")
//	sodium.BenchCurve25519()

//	g := sodium.NewCurve25519()
//	crypto.TestGroup(g)
//	return

	//testSuites()
	benchSuites()
}

