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

import "flag"

// Start decides on the '--simul'-flag whether it needs to build or start the
// simulation.
func Start() {
	flag.Parse()
	if simul == "" {
		Build()
	} else {
		Simulate()
	}
}
