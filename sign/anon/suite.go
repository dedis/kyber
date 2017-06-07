package anon

import (
	"gopkg.in/dedis/kyber.v1"
)

type Suite interface {
	kyber.Group
	kyber.CipherFactory
	kyber.HashFactory
	kyber.Encoding
}
