package main

import (
	"dissent/crypto"
	"dissent/crypto/openssl"
	"dissent/crypto/ed25519"
	"dissent/crypto/sodium"
)


func testSuites() {
	// Native Go suites
	crypto.TestSuite(crypto.NewAES128SHA256QR512())
	//crypto.TestSuite(crypto.NewAES128SHA256QR1024())
	crypto.TestSuite(crypto.NewAES128SHA256P256())
	crypto.TestSuite(crypto.NewAES128SHA256Ed25519())
	crypto.TestSuite(ed25519.NewAES128SHA256Ed25519())

	// OpenSSL-based suites
	crypto.TestSuite(openssl.NewAES128SHA256P256())
	crypto.TestSuite(openssl.NewAES192SHA384P384())
	crypto.TestSuite(openssl.NewAES256SHA512P521())
}

func benchSuites() {
	println("\nNative QR512 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256QR512())

	println("\nNative P256 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL P256 suite:")
	crypto.BenchSuite(openssl.NewAES128SHA256P256())

	println("\nNative Ed25519 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256Ed25519())

	println("\nOptimized Ed25519 suite:")
	crypto.BenchSuite(ed25519.NewAES128SHA256Ed25519())

	//println("\nSodium Ed25519 suite:")
	//crypto.BenchSuite(sodium.NewAES128SHA256Ed25519())
	//sodium.BenchCurve25519()
}

func main() {
	println("\nNative P256 suite:")
	crypto.BenchSuite(openssl.NewAES128SHA256P256())
	println("\nOptimized Ed25519 suite:")
	crypto.BenchSuite(ed25519.NewAES128SHA256Ed25519())
	println("\nSodium Ed25519 suite:")
	sodium.BenchCurve25519()

//	g := sodium.NewCurve25519()
//	crypto.TestGroup(g)

	return

	//testSuites()
	benchSuites()
}

