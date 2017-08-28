package main

import (
	"testing"

	"github.com/dedis/onet/simul"
)

func TestSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Not running test because travis doesn't have sudo")
	}
	simul.Start("count.toml", "csv1.toml", "csv2.toml")
}
