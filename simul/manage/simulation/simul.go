package main

import (
	"errors"
	"strconv"

	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/kyber.v1/group/edwards25519"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/simul"
	"gopkg.in/dedis/onet.v2/simul/manage"
	"gopkg.in/dedis/onet.v2/simul/monitor"
)

/*
Defines the simulation for the count-protocol
*/

var suite = edwards25519.NewAES128SHA256Ed25519(false)

func init() {
	onet.SimulationRegister("Count", NewSimulation)
}

// Simulation only holds the BFTree simulation
type simulation struct {
	onet.SimulationBFTree
}

// NewSimulation returns the new simulation, where all fields are
// initialised using the config-file
func NewSimulation(config string) (onet.Simulation, error) {
	es := &simulation{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (e *simulation) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	e.CreateRoster(sc, hosts, 2000, suite)
	err := e.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Run is used on the destination machines and runs a number of
// rounds
func (e *simulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", e.Rounds)
	for round := 0; round < e.Rounds; round++ {
		log.Lvl1("Starting round", round)
		round := monitor.NewTimeMeasure("round")
		p, err := config.Overlay.CreateProtocol("Count", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}
		go p.Start()
		children := <-p.(*manage.ProtocolCount).Count
		round.Record()
		if children != size {
			return errors.New("Didn't get " + strconv.Itoa(size) +
				" children")
		}
	}
	return nil
}

func main() {
	simul.Start(suite)
}
