package xof

import (
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/xof/keccak"
	"github.com/dedis/kyber/xof/norx"
)

type spongeFactory func() kyber.Sponge

var sponges = make(map[string]spongeFactory)

// the last registered becomes the default
var defaultSponge = ""

func register(name string, factory spongeFactory) {
	if _, ok := sponges[name]; ok {
		panic(fmt.Sprintf("Cannot sponge register %v twice.", name))
	}
	sponges[name] = factory
	defaultSponge = name
}

func init() {
	register("norx", func() kyber.Sponge { return norx.NewSponge() })
	register("keccak", func() kyber.Sponge { return keccak.NewKeccak1024() })
}
