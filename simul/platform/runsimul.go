package platform

import (
	"sync"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet/network"
	"github.com/dedis/onet/simul/manage"
	"github.com/dedis/onet/simul/monitor"
)

type simulInit struct{}
type simulInitDone struct{}

// Simulate starts the server and will setup the protocol.
func Simulate(serverAddress, simul, monitorAddress string) error {
	scs, err := onet.LoadSimulationConfig(".", serverAddress)
	if err != nil {
		// We probably are not needed
		log.Lvl2(err, serverAddress)
		return nil
	}
	measures := make([]*monitor.CounterIOMeasure, len(scs))
	if monitorAddress != "" {
		if err := monitor.ConnectSink(monitorAddress); err != nil {
			log.Error("Couldn't connect monitor to sink:", err)
		}
	}
	sims := make([]onet.Simulation, len(scs))
	simulInitID := network.RegisterMessage(simulInit{})
	simulInitDoneID := network.RegisterMessage(simulInitDone{})
	var rootSC *onet.SimulationConfig
	var rootSim onet.Simulation
	// having a waitgroup so the binary stops when all servers are closed
	var wgServer, wgSimulInit sync.WaitGroup
	var ready = make(chan bool)
	measureNodeBW := true
	if len(scs) > 0 {
		cfg := &conf{}
		_, err := toml.Decode(scs[0].Config, cfg)
		if err != nil {
			return err
		}
		measureNodeBW = cfg.IndividualStats == ""
	}
	for i, sc := range scs {
		// Starting all servers for that server
		server := sc.Server
		log.Lvl3(serverAddress, "Starting server", server.ServerIdentity.Address)
		if measureNodeBW {
			measures[i] = monitor.NewCounterIOMeasure("bandwidth", server)
		}
		// Launch a server and notifies when it's done
		wgServer.Add(1)
		go func(c *onet.Server, m monitor.Measure) {
			ready <- true
			defer wgServer.Done()
			c.Start()
			// record bandwidth, except if we're measuring every
			// round individually
			if measureNodeBW {
				m.Record()
			}
			log.Lvl3(serverAddress, "Simulation closed server", c.ServerIdentity)
		}(server, measures[i])
		// wait to be sure the goroutine started
		<-ready

		sim, err := onet.NewSimulation(simul, sc.Config)
		if err != nil {
			return err
		}
		sims[i] = sim
		// Need to store sc in a tmp-variable so it's correctly passed
		// to the Register-functions.
		scTmp := sc
		server.RegisterProcessorFunc(simulInitID, func(env *network.Envelope) {
			err = sim.Node(scTmp)
			if err != nil {
				log.Error(err)
			}
			scTmp.Server.Send(env.ServerIdentity, &simulInitDone{})
		})
		server.RegisterProcessorFunc(simulInitDoneID, func(env *network.Envelope) {
			wgSimulInit.Done()
		})
		if server.ServerIdentity.ID.Equal(sc.Tree.Root.ServerIdentity.ID) {
			log.Lvl2(serverAddress, "is root-node, will start protocol")
			rootSim = sim
			rootSC = sc
		}
	}
	if rootSim != nil {
		// If this cothority has the root-server, it will start the simulation
		log.Lvl2("Starting protocol", simul, "on server", rootSC.Server.ServerIdentity.Address)
		log.Lvl5("Tree is", rootSC.Tree.Dump())

		// First count the number of available children
		childrenWait := monitor.NewTimeMeasure("ChildrenWait")
		wait := true
		// The timeout starts with 1 second, which is the time of response between
		// each level of the tree.
		timeout := 1000
		for wait {
			p, err := rootSC.Overlay.CreateProtocol("Count", rootSC.Tree, onet.NilServiceID)
			if err != nil {
				return err
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
		log.Lvl2("Broadcasting start")
		syncWait := monitor.NewTimeMeasure("SimulSyncWait")
		wgSimulInit.Add(len(rootSC.Tree.Roster.List))
		for _, conode := range rootSC.Tree.Roster.List {
			go rootSC.Server.Send(conode, &simulInit{})
		}
		wgSimulInit.Wait()
		syncWait.Record()
		log.Lvl1("Starting new node", simul)
		measureNet := monitor.NewCounterIOMeasure("bandwidth_root", rootSC.Server)
		err := rootSim.Run(rootSC)
		if err != nil {
			return err
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
		pi, err := rootSC.Overlay.CreateProtocol("CloseAll", closeTree, onet.NilServiceID)
		pi.Start()
		if err != nil {
			return err
		}
	}

	log.Lvl3(serverAddress, scs[0].Server.ServerIdentity, "is waiting for all servers to close")
	wgServer.Wait()
	log.Lvl2(serverAddress, "has all servers closed")
	if monitorAddress != "" {
		monitor.EndAndCleanup()
	}
	return nil
}

type conf struct {
	IndividualStats string
}
