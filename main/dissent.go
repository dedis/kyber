package main

import "dissent/crypto"
import "dissent/crypto/openssl"

func main() {
	crypto.TestSuite(crypto.NewAES128SHA256QR512())
	//crypto.TestSuite(crypto.NewAES128SHA256QR1024())
	crypto.TestSuite(crypto.NewAES128SHA256P256())
	crypto.TestSuite(openssl.NewAES128SHA256P256())

	println("\nNative QR512 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256QR512())

	println("\nNative P256 suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL P256 suite:")
	crypto.BenchSuite(openssl.NewAES128SHA256P256())
}

