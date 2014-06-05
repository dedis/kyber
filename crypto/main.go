package main

import (
	"encoding/hex"
)

import "fmt"


func main() {
	cs1 := CipherSuite1{}

	var cs CipherSuite = cs1
	h := cs.Hash([]byte("abc"))

	fmt.Println(hex.Dump(h))

	TestSchnorrGroup()
}

