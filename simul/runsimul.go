package simul

import (
	"flag"
	"sync"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"

	"github.com/dedis/onet/simul/manage"
	"github.com/dedis/onet/simul/monitor"
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

// Main starts the conode and will setup the protocol.
func simulate() {
	flag.Parse()
	log.Lvl3("Flags are:", conodeAddress, simul, log.DebugVisible, monitorAddress)

	scs, err := onet.LoadSimulationConfig(".", conodeAddress)
	measures := make([]*monitor.CounterIOMeasure, len(scs))
	if err != nil {
		// We probably are not needed
		log.Lvl2(err, conodeAddress)
		return
	}
	if monitorAddress != "" {
		if err := monitor.ConnectSink(monitorAddress); err != nil {
			log.Error("Couldn't connect monitor to sink:", err)
		}
	}
	sims := make([]onet.Simulation, len(scs))
	var rootSC *onet.SimulationConfig
	var rootSim onet.Simulation
	// having a waitgroup so the binary stops when all conodes are closed
	var wg sync.WaitGroup
	var ready = make(chan bool)
	for i, sc := range scs {
		// Starting all conodes for that server
		conode := sc.Conode
		measures[i] = monitor.NewCounterIOMeasure("bandwidth", conode)
		log.Lvl3(conodeAddress, "Starting conode", conode.ServerIdentity.Address)
		// Launch a conode and notifies when it's done

		wg.Add(1)
		go func(c *onet.Conode, m monitor.Measure) {
			ready <- true
			defer wg.Done()
			c.Start()
			// record bandwidth
			m.Record()
			log.Lvl3(conodeAddress, "Simulation closed conode", c.ServerIdentity)
		}(conode, measures[i])
		// wait to be sure the goroutine started
		<-ready

		sim, err := onet.NewSimulation(simul, sc.Config)
		if err != nil {
			log.Fatal(err)
		}
		err = sim.Node(sc)
		if err != nil {
			log.Fatal(err)
		}
		sims[i] = sim
		if conode.ServerIdentity.ID == sc.Tree.Root.ServerIdentity.ID {
			log.Lvl2(conodeAddress, "is root-node, will start protocol")
			rootSim = sim
			rootSC = sc
		}
	}
	if rootSim != nil {
		// If this cothority has the root-conode, it will start the simulation
		log.Lvl2("Starting protocol", simul, "on conode", rootSC.Conode.ServerIdentity.Address)
		//log.Lvl5("Tree is", rootSC.Tree.Dump())

		// First count the number of available children
		childrenWait := monitor.NewTimeMeasure("ChildrenWait")
		wait := true
		// The timeout starts with 1 second, which is the time of response between
		// each level of the tree.
		timeout := 1000
		for wait {
			p, err := rootSC.Overlay.CreateProtocolOnet("Count", rootSC.Tree)
			if err != nil {
				log.Fatal(err)
			}
			proto := p.(*manage.ProtocolCount)
			proto.SetTimeout(timeout)
			proto.Start()
			log.Lvl1("Started counting children with timeout of", timeout)
			select {
			case count := <-proto.Count:
				if count == rootSC.Tree.Size() {
					log.Lvl1("Found all", count, "children")
					wait = false
				} else {
					log.Lvl1("Found only", count, "children, counting again")
				}
			}
			// Double the timeout and try again if not successful.
			timeout *= 2
		}
		childrenWait.Record()
		log.Lvl1("Starting new node", simul)
		measureNet := monitor.NewCounterIOMeasure("bandwidth_root", rootSC.Conode)
		err := rootSim.Run(rootSC)
		if err != nil {
			log.Fatal(err)
		}
		measureNet.Record()

		// Test if all ServerIdentities are used in the tree, else we'll run into
		// troubles with CloseAll
		if !rootSC.Tree.UsesList() {
			log.Error("The tree doesn't use all ServerIdentities from the list!\n" +
				"This means that the CloseAll will fail and the experiment never ends!")
		}
		closeTree := rootSC.Tree
		if rootSC.GetSingleHost() {
			// In case of "SingleHost" we need a new tree that contains every
			// entity only once, whereas rootSC.Tree will have the same
			// entity at different TreeNodes, which makes it difficult to
			// correctly close everything.
			log.Lvl2("Making new root-tree for SingleHost config")
			closeTree = rootSC.Roster.GenerateBinaryTree()
			rootSC.Overlay.RegisterTree(closeTree)
		}
		pi, err := rootSC.Overlay.CreateProtocolOnet("CloseAll", closeTree)
		pi.Start()
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Lvl3(conodeAddress, scs[0].Conode.ServerIdentity, "is waiting for all conodes to close")
	wg.Wait()
	log.Lvl2(conodeAddress, "has all conodes closed")
	monitor.EndAndCleanup()
}
