package main

import "dissent/crypto"
import "dissent/crypto/openssl"

func main() {
	crypto.TestSuite(crypto.NewAES128SHA256QR2048())
	crypto.TestSuite(crypto.NewAES128SHA256P256())
	crypto.TestSuite(openssl.NewAES128SHA256P256())

	println("\nNative suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL suite:")
	crypto.BenchSuite(openssl.NewAES128SHA256P256())
}

