package main

import (
	"dissent/crypto"
	"dissent/crypto/openssl"
)


func testSuites() {
	// Native Go suites
	crypto.TestSuite(crypto.NewAES128SHA256QR512())
	//crypto.TestSuite(crypto.NewAES128SHA256QR1024())
	crypto.TestSuite(crypto.NewAES128SHA256P256())

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
}

func main() {

	testSuites()

	//benchSuites()
}

