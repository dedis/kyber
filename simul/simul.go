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
	"os"

	"github.com/dedis/onet/log"
)

// Start has to be called by the main-file that imports the protocol and/or the
// service. If a user calls the simulation-file, `simul` is empty, and the
// build is started.
// Only the platform will call this binary with a simul-flag set to the name of the
// simulation to run.
// If given an array of rcs, each element will be interpreted as a .toml-file
// to load and simulate.
func Start(rcs ...string) {
	if len(rcs) > 0 {
		wd, err := os.Getwd()
		log.ErrFatal(err)
		for _, rc := range rcs {
			log.Lvl1("Running toml-file:", rc)
			os.Args = []string{os.Args[0], rc}
			Start()
			os.Chdir(wd)
		}
	}
	flag.Parse()
	if simul == "" {
		startBuild()
	} else {
		simulate()
	}
}
