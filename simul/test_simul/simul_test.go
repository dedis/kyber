package main

import (
	"testing"

	"gopkg.in/dedis/onet.v2/simul"
)

func TestSimulation(t *testing.T) {
	simul.Start("count.toml")
}
