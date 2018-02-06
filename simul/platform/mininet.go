// Mininet is the platform-implementation that uses the MiniNet-framework
// set in place by Marc-Andre Luthi from EPFL. It is based on MiniNet,
// as it uses a lot of similar routines

package platform

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
)

// MiniNet represents all the configuration that is necessary to run a simulation
// on remote hosts running Mininet.
type MiniNet struct {
	// *** Mininet-related configuration
	// The login on the platform
	Login string
	// The outside host on the platform
	External string
	// Directory we start - the simulation-directory of the service/protocol
	wd string
	// Directory holding the simulation main-file
	simulDir string
	// Directory storing the additional files
	mininetDir string
	// Directory for building
	buildDir string
	// Directory for deploying
	deployDir string
	// IPs of all hosts
	HostIPs []string
	// Channel to communicate stopping of experiment
	sshMininet chan string
	// Whether the simulation is started
	started bool
	// RC-configuration
	config string

	// ProxyAddress : the proxy will redirect every traffic it
	// receives to this address
	ProxyAddress string
	// Port number of the monitor and the proxy
	MonitorPort int

	// Simulation to be run
	Simulation string
	// Number of servers to be used
	Servers int
	// Number of machines
	Hosts int
	// Debugging-level: 0 is none - 5 is everything
	Debug int
	// Whether to show time in debugging messages
	DebugTime bool
	// Whether to show color debugging-messages
	DebugColor bool
	// The number of seconds to wait for closing the connection
	RunWait time.Duration
	// Delay in ms of the network connection
	Delay int
	// Bandwidth in Mbps of the network connection
	Bandwidth int
	// Suite used for the simulation
	Suite string
	// PreScript defines a script that is run before the simulation
	PreScript string
}

// Configure implements the Platform-interface. It is called once to set up
// the necessary internal variables.
func (m *MiniNet) Configure(pc *Config) {
	// Directory setup - would also be possible in /tmp
	m.wd, _ = os.Getwd()
	m.simulDir = m.wd
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("Couldn't get my path")
	}
	var err error
	m.Suite = pc.Suite
	m.mininetDir, err = filepath.Abs(path.Dir(filename))
	log.ErrFatal(err)
	m.mininetDir = filepath.Join(m.mininetDir, "mininet")
	m.buildDir = m.wd + "/build"
	m.deployDir = m.wd + "/deploy"
	m.Login = "root"
	log.ErrFatal(m.parseServers())
	m.External = m.HostIPs[0]
	m.ProxyAddress = "localhost"
	m.MonitorPort = pc.MonitorPort
	m.Debug = pc.Debug
	m.DebugTime = log.ShowTime()
	m.DebugColor = log.UseColors()

	m.Delay = 0
	m.Bandwidth = 1000

	// Clean the build- and deploy-dir, then (re-)create them
	for _, d := range []string{m.buildDir, m.deployDir} {
		os.RemoveAll(d)
		log.ErrFatal(os.Mkdir(d, 0700))
	}
	onet.WriteTomlConfig(*m, "mininet.toml", m.buildDir)

	if m.Simulation == "" {
		log.Fatal("No simulation defined in runconfig")
	}

	// Setting up channel
	m.sshMininet = make(chan string)
}

// Build implements the Platform interface and is called once per runlevel-file.
// build is the name of the app to build
// empty = all otherwise build specific package
func (m *MiniNet) Build(build string, arg ...string) error {
	log.Lvl1("Building for", m.Login, m.External, build, "simulDir=", m.simulDir)
	start := time.Now()

	// Start with a clean build-directory
	processor := "amd64"
	system := "linux"
	srcRel, err := filepath.Rel(m.wd, m.simulDir)
	log.ErrFatal(err)

	log.Lvl3("Relative-path is", srcRel, ". Will build into", m.buildDir)
	out, err := Build("./"+srcRel, m.buildDir+"/conode",
		processor, system, arg...)
	log.ErrFatal(err, out)

	log.Lvl1("Build is finished after", time.Since(start))
	return nil
}

// Cleanup kills all eventually remaining processes from the last Deploy-run
func (m *MiniNet) Cleanup() error {
	// Cleanup eventual ssh from the proxy-forwarding to the logserver
	err := exec.Command("pkill", "-9", "-f", "ssh -nNTf").Run()
	if err != nil {
		log.Lvl3("Error stopping ssh:", err)
	}

	// SSH to the MiniNet-server and end all running users-processes
	log.Lvl3("Going to stop everything")
	log.ErrFatal(m.parseServers())
	for _, h := range m.HostIPs {
		log.Lvl3("Cleaning up server", h)
		_, err = SSHRun(m.Login, m.External, "pkill -9 -f start.py; mn -c; killall sshd")
		if err != nil {
			log.Lvl2("Error while cleaning up:", err)
		}
	}
	return nil
}

// Deploy creates the appropriate configuration-files and copies everything to the
// MiniNet-installation.
func (m *MiniNet) Deploy(rc *RunConfig) error {
	log.Lvl2("Localhost: Deploying and writing config-files")
	sim, err := onet.NewSimulation(m.Simulation, string(rc.Toml()))
	if err != nil {
		return err
	}

	// Check for PreScript and copy it to the deploy-dir
	m.PreScript = rc.Get("PreScript")
	if m.PreScript != "" {
		_, err := os.Stat(m.PreScript)
		if !os.IsNotExist(err) {
			if err := app.Copy(m.deployDir, m.PreScript); err != nil {
				return err
			}
		}
	}

	// Initialize the mininet-struct with our current structure (for debug-levels
	// and such), then read in the app-configuration to overwrite eventual
	// 'Servers', 'Hosts', '' or other fields
	mininet := *m
	mininetConfig := m.deployDir + "/mininet.toml"
	_, err = toml.Decode(string(rc.Toml()), &mininet)
	if err != nil {
		return err
	}
	log.Lvl3("Writing the config file :", mininet)
	onet.WriteTomlConfig(mininet, mininetConfig, m.deployDir)

	log.Lvl3("Creating hosts")
	if err = m.parseServers(); err != nil {
		return err
	}
	hosts, list, err := m.getHostList(rc)
	if err != nil {
		return err
	}
	log.Lvl3("Hosts are:", hosts)
	log.Lvl3("List is:", list)
	err = ioutil.WriteFile(m.deployDir+"/list", []byte(list), 0660)
	if err != nil {
		return err
	}
	simulConfig, err := sim.Setup(m.deployDir, hosts)
	if err != nil {
		return err
	}
	simulConfig.Config = string(rc.Toml())
	m.config = simulConfig.Config
	log.Lvl3("Saving configuration")
	simulConfig.Save(m.deployDir)

	// Verify the installation is correct
	gw := m.HostIPs[0]
	log.Lvl2("Verifying configuration on", gw)
	out, err := exec.Command("ssh", "root@"+gw, "which mn").Output()
	if err != nil || !strings.HasSuffix(string(out), "mn\n") {
		log.Error("While trying to connect to", gw, err)
		log.Fatal("Please verify installation of mininet or run\n" +
			"./platforms/mininet/setup_iccluster.sh")
	}

	// Copy our script
	err = app.Copy(m.deployDir, m.mininetDir+"/start.py")
	if err != nil {
		log.Error(err)
		return err
	}

	// Copy conode-binary
	err = app.Copy(m.deployDir, m.buildDir+"/conode")
	if err != nil {
		log.Error(err)
		return err
	}

	// Copy everything over to MiniNet
	log.Lvl1("Copying over to", m.Login, "@", m.External)
	err = Rsync(m.Login, m.External, m.deployDir+"/", "mininet_run/")
	if err != nil {
		log.Fatal(err)
	}
	log.Lvl2("Done copying")

	return nil
}

// Start connects to the first of the remote servers to start the simulation.
func (m *MiniNet) Start(args ...string) error {
	// setup port forwarding for viewing log server
	m.started = true
	// Remote tunneling : the sink port is used both for the sink and for the
	// proxy => the proxy redirects packets to the same port the sink is
	// listening.
	// -n = stdout == /Dev/null, -N => no command stream, -T => no tty
	var exCmd *exec.Cmd
	redirection := fmt.Sprintf("*:%d:%s:%d", m.MonitorPort, m.ProxyAddress, m.MonitorPort)
	login := fmt.Sprintf("%s@%s", m.Login, m.External)
	cmd := []string{"-nNTf", "-o", "StrictHostKeyChecking=no", "-o", "ExitOnForwardFailure=yes", "-R",
		redirection, login}
	exCmd = exec.Command("ssh", cmd...)
	if err := exCmd.Start(); err != nil {
		log.Fatal("Failed to start the ssh port forwarding:", err)
	}
	if err := exCmd.Wait(); err != nil {
		log.Fatal("ssh port forwarding exited in failure:", err)
	}
	go func() {
		config := strings.Split(m.config, "\n")
		sort.Strings(config)
		log.Lvlf1("Starting simulation %s over mininet", strings.Join(config, " :: "))
		err := SSHRunStdout(m.Login, m.External, "cd mininet_run; ./start.py list go")
		if err != nil {
			log.Lvl3(err)
		}
		m.sshMininet <- "finished"
	}()

	return nil
}

// Wait blocks on the channel till the main-process finishes.
func (m *MiniNet) Wait() error {
	wait := m.RunWait
	if wait == 0 {
		wait = 600 * time.Second
	}
	if m.started {
		log.Lvl3("Simulation is started")
		select {
		case msg := <-m.sshMininet:
			if msg == "finished" {
				log.Lvl3("Received finished-message, not killing users")
				return nil
			}
			log.Lvl1("Received out-of-line message", msg)
		case <-time.After(wait):
			log.Lvl1("Quitting after waiting", wait)
			m.started = false
		}
		m.started = false
	}
	return nil
}

// Returns the servers to use for mininet.
func (m *MiniNet) parseServers() error {
	slName := path.Join(m.wd, "server_list")
	hosts, err := ioutil.ReadFile(slName)
	if err != nil {
		return fmt.Errorf("Couldn't find %s - you can produce one with\n"+
			"\t\t%[2]s/setup_servers.sh\n\t\tor\n\t\t%[2]s/setup_iccluster.sh", slName, m.mininetDir)
	}
	m.HostIPs = []string{}
	for _, hostRaw := range strings.Split(string(hosts), "\n") {
		h := strings.Replace(hostRaw, " ", "", -1)
		if len(h) > 0 {
			ips, err := net.LookupIP(h)
			if err != nil {
				return err
			}
			log.Lvl3("Found IP for", h, ":", ips[0])
			m.HostIPs = append(m.HostIPs, ips[0].String())
		}
	}
	log.Lvl3("Nodes are:", m.HostIPs)
	return nil
}

// getHostList prepares the mapping from physical hosts to mininet-hosts. Each
// physical host holds a 10.x/16-network with the .0.1 being the gateway and
// .0.2 the first usable conode.
//
// hosts holds all addresses for all conodes, attributed in a round-robin fashion
// over all mininet-addresses.
//
// list is used by platform/mininet/start.py and has the following format:
// SimulationName BandwidthMbps DelayMS
// physicalIP1 MininetNet1/16 NumberConodes1
// physicalIP2 MininetNet2/16 NumberConodes2
func (m *MiniNet) getHostList(rc *RunConfig) (hosts []string, list string, err error) {
	hosts = []string{}
	list = ""
	physicalServers := len(m.HostIPs)
	nets := make([]*net.IPNet, physicalServers)
	ips := make([]net.IP, physicalServers)

	// Create all mininet-networks
	for n := range nets {
		ips[n], nets[n], err = net.ParseCIDR(fmt.Sprintf("10.%d.0.0/16", n+1))
		if err != nil {
			return
		}
		// We'll have to start with 10.1.0.2 as the first host.
		// So we set the LSByte to 1 which will be increased later.
		ips[n][len(ips[n])-1] = byte(1)
	}
	hosts = []string{}
	nbrServers, err := rc.GetInt("Servers")
	if err != nil {
		return
	}
	if nbrServers > physicalServers {
		log.Warn(nbrServers, "servers requested, but only", physicalServers,
			"available - proceeding anyway.")
	}
	nbrHosts, err := rc.GetInt("Hosts")
	if err != nil {
		return
	}

	// Map all required conodes to Mininet-hosts
	for i := 0; i < nbrHosts; i++ {
		ip := ips[i%physicalServers]
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
		ips[i%physicalServers] = ip
		hosts = append(hosts, ip.String())
	}

	bandwidth := m.Bandwidth
	if bw, err := rc.GetInt("Bandwidth"); err == nil {
		bandwidth = bw
	}
	delay := m.Delay
	if d, err := rc.GetInt("Delay"); err == nil {
		delay = d
	}
	list = fmt.Sprintf("%s %d %d\n%d %t %t\n%s\n", m.Simulation, bandwidth, delay,
		m.Debug, m.DebugTime, m.DebugColor, m.PreScript)

	// Add descriptions for `start.py` to know which mininet-network it has to
	// run on what physical server with how many hosts.
	for i, s := range nets {
		if i >= nbrHosts {
			break
		}
		// Magical formula to get how many hosts run on each
		// physical server if we distribute them evenly, starting
		// from the first server.
		h := (nbrHosts + physicalServers - 1 - i) / physicalServers
		list += fmt.Sprintf("%s %s %d\n",
			m.HostIPs[i], s.String(), h)
	}
	return
}
