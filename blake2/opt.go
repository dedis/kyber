package blake2

import (
	"hash"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/blake2/opt"
)

// Create a new BLAKE2 sponge cipher,
// using the optimized C implementation in crypto.blake2.opt.
func NewSponge() abstract.Sponge {
	return abstract.Sponge{opt.NewState()}
}

func NewBlake2b() hash.Hash {
	h := spongeHash{}
	h.Init(opt.NewState())
	return &h
}

