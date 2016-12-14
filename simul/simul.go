/*
Package simul allows for easy simulation on different platforms. THe following platforms
are available:

	- localhost - for up to 100 nodes
	- mininet - for up to 1'000 nodes
	- deterlab - for up to 50'000 nodes

Usually you start small, then work your way up to the full potential of your
protocol!
*/
package simul

import (
	"flag"

	"github.com/dedis/onet/simul/platform"
)

var deterlabUser bool

func init() {
	flag.BoolVar(&deterlabUser, "deteruser", false, "start as deterlab-user-binary")
}

// Start decides on the '--simul'-flag whether it needs to build or start the
// simulation and the '--user' to start in deterlab-user-mode.
func Start() {
	flag.Parse()
	switch {
	case simul != "":
		Simulate()
	case deterlabUser:
		platform.DeterlabUser()
	default:
		Build()
	}
}
