package main

import (
	"testing"

	"github.com/dedis/onet/simul"
)

func TestSimulation(t *testing.T) {
	simul.Start("count.toml", "csv1.toml", "csv2.toml")
}
