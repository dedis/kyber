package openssl

import (
	"testing"
	"dissent/crypto"
)

func BenchmarkAES128(b *testing.B) {
	crypto.BlockCipherBench(b, 16, NewAES)
}               
                
func BenchmarkAES192(b *testing.B) {
	crypto.BlockCipherBench(b, 24, NewAES)
}       

func BenchmarkAES256(b *testing.B) {
	crypto.BlockCipherBench(b, 32, NewAES)
}


/*
func BenchmarkAES128CTR(b *testing.B) {
	crypto.StreamCipherBench(b, 16, newAESCTR)
}               
                
func BenchmarkAES192CTR(b *testing.B) {
	crypto.StreamCipherBench(b, 24, newAESCTR)
}       

func BenchmarkAES256CTR(b *testing.B) {
	crypto.StreamCipherBench(b, 32, newAESCTR)
}
*/


func BenchmarkSHA1(b *testing.B) {
	crypto.HashBench(b, NewSHA1)
}               

func BenchmarkSHA224(b *testing.B) {
	crypto.HashBench(b, NewSHA224)
}               

func BenchmarkSHA256(b *testing.B) {
	crypto.HashBench(b, NewSHA256)
}               

func BenchmarkSHA384(b *testing.B) {
	crypto.HashBench(b, NewSHA384)
}               

func BenchmarkSHA512(b *testing.B) {
	crypto.HashBench(b, NewSHA512)
}               

