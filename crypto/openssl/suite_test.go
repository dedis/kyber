package openssl

import (
	"testing"
	"dissent/crypto/bench"
)

func BenchmarkAES128(b *testing.B) {
	bench.BlockCipherBench(b, 16, NewAES)
}               
                
func BenchmarkAES192(b *testing.B) {
	bench.BlockCipherBench(b, 24, NewAES)
}       

func BenchmarkAES256(b *testing.B) {
	bench.BlockCipherBench(b, 32, NewAES)
}


func BenchmarkSHA1(b *testing.B) {
	bench.HashBench(b, NewSHA1)
}               

func BenchmarkSHA224(b *testing.B) {
	bench.HashBench(b, NewSHA224)
}               

func BenchmarkSHA256(b *testing.B) {
	bench.HashBench(b, NewSHA256)
}               

func BenchmarkSHA384(b *testing.B) {
	bench.HashBench(b, NewSHA384)
}               

func BenchmarkSHA512(b *testing.B) {
	bench.HashBench(b, NewSHA512)
}               

