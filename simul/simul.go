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
	"github.com/dedis/onet/simul/platform"
)

// The address of this conode - if there is only one conode in the config
// file, it will be derived from it automatically
var conodeAddress string

// ip addr of the logger to connect to
var monitorAddress string

// Simul is != "" if this node needs to start a simulation of that protocol
var simul string

// Initialize before 'init' so we can directly use the fields as parameters
// to 'Flag'
func init() {
	flag.StringVar(&conodeAddress, "address", "", "our address to use")
	flag.StringVar(&simul, "simul", "", "start simulating that protocol")
	flag.StringVar(&monitorAddress, "monitor", "", "remote monitor")
}

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
		err := platform.Simulate(conodeAddress, simul, monitorAddress)
		log.ErrFatal(err)
	}
}
