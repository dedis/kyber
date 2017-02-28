// Deterlab is responsible for setting up everything to test the application
// on deterlab.net
// Given a list of hostnames, it will create an overlay
// tree topology, using all but the last node. It will create multiple
// nodes per server and run timestamping processes. The last node is
// reserved for the logging server, which is forwarded to localhost:8081
//
// Creates the following directory structure:
// build/ - where all cross-compiled executables are stored
// remote/ - directory to be copied to the deterlab server
//
// The following apps are used:
//   deter - runs on the user-machine in deterlab and launches the others
//   forkexec - runs on the other servers and launches the app, so it can measure its cpu usage

package platform

import (
	"os"
	"os/exec"
	"strings"
	"sync"

	"bufio"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"time"

	"os/user"

	"runtime"

	"path/filepath"

	"errors"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// Deterlab holds all fields necessary for a Deterlab-run
type Deterlab struct {
	// *** Deterlab-related configuration
	// The login on the platform
	Login string
	// The outside host on the platform
	Host string
	// The name of the project
	Project string
	// Name of the Experiment - also name of hosts
	Experiment string
	// Directory holding the simulation-main file
	simulDir string
	// Directory where the deterlab-users-file is held
	usersDir string
	// Directory where everything is copied into
	deployDir string
	// Directory for building
	buildDir string
	// Directory holding all go-files of onet/simul/platform
	platformDir string
	// DNS-resolvable names
	Phys []string
	// VLAN-IP names (physical machines)
	Virt []string
	// Channel to communication stopping of experiment
	sshDeter chan string
	// Whether the simulation is started
	started bool

	// ProxyAddress : the proxy will redirect every traffic it
	// receives to this address
	ProxyAddress string
	// MonitorAddress is the address given to clients to connect to the monitor
	// It is actually the Proxy that will listen to that address and clients
	// won't know a thing about it
	MonitorAddress string
	// Port number of the monitor and the proxy
	MonitorPort int

	// Number of available servers
	Servers int
	// Name of the simulation
	Simulation string
	// Number of machines
	Hosts int
	// Debugging-level: 0 is none - 5 is everything
	Debug int
	// RunWait for long simulations
	RunWait int
}

var simulConfig *onet.SimulationConfig

// Configure initialises the directories and loads the saved config
// for Deterlab
func (d *Deterlab) Configure(pc *Config) {
	// Directory setup - would also be possible in /tmp
	pwd, _ := os.Getwd()
	d.simulDir = pwd
	d.deployDir = pwd + "/deploy"
	d.buildDir = pwd + "/build"
	_, file, _, _ := runtime.Caller(0)
	d.platformDir = path.Dir(file)
	os.RemoveAll(d.deployDir)
	os.Mkdir(d.deployDir, 0770)
	os.Mkdir(d.buildDir, 0770)
	d.MonitorPort = pc.MonitorPort
	log.Lvl3("Dirs are:", pwd, d.deployDir)
	d.loadAndCheckDeterlabVars()

	d.Debug = pc.Debug
	if d.Simulation == "" {
		log.Fatal("No simulation defined in runconfig")
	}

	// Setting up channel
	d.sshDeter = make(chan string)
}

type pkg struct {
	name      string
	processor string
	system    string
	path      string
}

// Build prepares all binaries for the Deterlab-simulation.
// If 'build' is empty, all binaries are created, else only
// the ones indicated. Either "simul" or "users"
func (d *Deterlab) Build(build string, arg ...string) error {
	log.Lvl1("Building for", d.Login, d.Host, d.Project, build, "simulDir=", d.simulDir)
	start := time.Now()

	var wg sync.WaitGroup

	if err := os.RemoveAll(d.buildDir); err != nil {
		return err
	}
	if err := os.Mkdir(d.buildDir, 0777); err != nil {
		return err
	}

	// start building the necessary binaries - it's always the same,
	// but built for another architecture.
	packages := []pkg{
		{"simul", "amd64", "linux", d.simulDir},
		{"users", "386", "freebsd", path.Join(d.platformDir, "deterlab_users")},
	}
	if build == "" {
		build = "simul,users"
	}
	log.Lvl3("Starting to build all executables", packages)
	for _, p := range packages {
		if !strings.Contains(build, p.name) {
			log.Lvl2("Skipping build of", p.name)
			continue
		}
		log.Lvl3("Building", p)
		wg.Add(1)
		go func(p pkg) {
			defer wg.Done()
			dst := path.Join(d.buildDir, p.name)
			path, err := filepath.Rel(d.simulDir, p.path)
			log.ErrFatal(err)
			// deter has an amd64, linux architecture
			out, err := Build(path, dst,
				p.processor, p.system, arg...)
			if err != nil {
				KillGo()
				log.Lvl1(out)
				log.Fatal(err)
			}
		}(p)
	}
	// wait for the build to finish
	wg.Wait()
	log.Lvl1("Build is finished after", time.Since(start))
	return nil
}

// Cleanup kills all eventually remaining processes from the last Deploy-run
func (d *Deterlab) Cleanup() error {
	// Cleanup eventual ssh from the proxy-forwarding to the logserver
	err := exec.Command("pkill", "-9", "-f", "ssh -nNTf").Run()
	if err != nil {
		log.Lvl3("Error stopping ssh:", err)
	}

	// SSH to the deterlab-server and end all running users-processes
	log.Lvl3("Going to kill everything")
	var sshKill chan string
	sshKill = make(chan string)
	go func() {
		// Cleanup eventual residues of previous round - users and sshd
		if _, err := SSHRun(d.Login, d.Host, "killall -9 users sshd"); err != nil {
			log.Lvl3("Error while cleaning up:", err)
		}

		err := SSHRunStdout(d.Login, d.Host, "test -f remote/users && ( cd remote; ./users -kill )")
		if err != nil {
			log.Lvl1("NOT-Normal error from cleanup")
			sshKill <- "error"
		}
		sshKill <- "stopped"
	}()

	for {
		select {
		case msg := <-sshKill:
			if msg == "stopped" {
				log.Lvl3("Users stopped")
				return nil
			}
			log.Lvl2("Received other command", msg, "probably the app didn't quit correctly")
		case <-time.After(time.Second * 20):
			log.Lvl3("Timeout error when waiting for end of ssh")
			return nil
		}
	}
}

// Deploy creates the appropriate configuration-files and copies everything to the
// deterlab-installation.
func (d *Deterlab) Deploy(rc *RunConfig) error {
	if err := os.RemoveAll(d.deployDir); err != nil {
		return err
	}
	if err := os.Mkdir(d.deployDir, 0777); err != nil {
		return err
	}

	log.Lvl2("Localhost: Deploying and writing config-files")
	sim, err := onet.NewSimulation(d.Simulation, string(rc.Toml()))
	if err != nil {
		return err
	}
	// Initialize the deter-struct with our current structure (for debug-levels
	// and such), then read in the app-configuration to overwrite eventual
	// 'Machines', 'ppm', '' or other fields
	deter := *d
	deterConfig := d.deployDir + "/deter.toml"
	_, err = toml.Decode(string(rc.Toml()), &deter)
	if err != nil {
		return err
	}
	log.Lvl3("Creating hosts")
	deter.createHosts()
	log.Lvl3("Writing the config file :", deter)
	onet.WriteTomlConfig(deter, deterConfig, d.deployDir)

	simulConfig, err = sim.Setup(d.deployDir, deter.Virt)
	if err != nil {
		return err
	}
	simulConfig.Config = string(rc.Toml())
	log.Lvl3("Saving configuration")
	if err := simulConfig.Save(d.deployDir); err != nil {
		log.Error("Couldn't save configuration:", err)
	}

	// Copy limit-files for more connections
	ioutil.WriteFile(path.Join(d.deployDir, "simul.conf"),
		[]byte(simulConnectionsConf), 0444)

	// Copying build-files to deploy-directory
	build, err := ioutil.ReadDir(d.buildDir)
	for _, file := range build {
		err = exec.Command("cp", d.buildDir+"/"+file.Name(), d.deployDir).Run()
		if err != nil {
			log.Fatal("error copying build-file:", d.buildDir, file.Name(), d.deployDir, err)
		}
	}

	// Copy everything over to Deterlab
	log.Lvl1("Copying over to", d.Login, "@", d.Host)
	err = Rsync(d.Login, d.Host, d.deployDir+"/", "remote/")
	if err != nil {
		log.Fatal(err)
	}
	log.Lvl2("Done copying")

	return nil
}

// Start creates a tunnel for the monitor-output and contacts the Deterlab-
// server to run the simulation
func (d *Deterlab) Start(args ...string) error {
	// setup port forwarding for viewing log server
	d.started = true
	// Remote tunneling : the sink port is used both for the sink and for the
	// proxy => the proxy redirects packets to the same port the sink is
	// listening.
	// -n = stdout == /Dev/null, -N => no command stream, -T => no tty
	redirection := strconv.Itoa(d.MonitorPort+1) + ":" + d.ProxyAddress + ":" + strconv.Itoa(d.MonitorPort)
	cmd := []string{"-nNTf", "-o", "StrictHostKeyChecking=no", "-o", "ExitOnForwardFailure=yes", "-R",
		redirection, fmt.Sprintf("%s@%s", d.Login, d.Host)}
	exCmd := exec.Command("ssh", cmd...)
	if err := exCmd.Start(); err != nil {
		log.Fatal("Failed to start the ssh port forwarding:", err)
	}
	if err := exCmd.Wait(); err != nil {
		log.Fatal("ssh port forwarding exited in failure:", err)
	}
	log.Lvl3("Setup remote port forwarding", cmd)
	go func() {
		err := SSHRunStdout(d.Login, d.Host, "cd remote; GOMAXPROCS=8 ./users")
		if err != nil {
			log.Lvl3(err)
		}
		d.sshDeter <- "finished"
	}()

	return nil
}

// Wait for the process to finish
func (d *Deterlab) Wait() error {
	wait := d.RunWait
	if wait == 0 {
		wait = 600
	}
	if d.started {
		log.Lvl3("Simulation is started")
		select {
		case msg := <-d.sshDeter:
			if msg == "finished" {
				log.Lvl3("Received finished-message, not killing users")
				return nil
			}
			log.Lvl1("Received out-of-line message", msg)
		case <-time.After(time.Second * time.Duration(wait)):
			log.Lvl1("Quitting after ", wait/60,
				" minutes of waiting")
			d.started = false
		}
		d.started = false
	}
	return nil
}

// Write the hosts.txt file automatically
// from project name and number of servers
func (d *Deterlab) createHosts() {
	// Query deterlab's API for servers
	log.Lvl2("Querying Deterlab's API to retrieve server names and addresses")
	command := fmt.Sprintf("/usr/testbed/bin/expinfo -l -e %s,%s", d.Project, d.Experiment)
	apiReply, err := SSHRun(d.Login, d.Host, command)
	if err != nil {
		log.Fatal("Error while querying Deterlab:", err)
	}
	log.ErrFatal(d.parseHosts(string(apiReply)))
}

func (d *Deterlab) parseHosts(str string) error {
	// Get the link-information, which is the second block in `expinfo`-output
	infos := strings.Split(str, "\n\n")
	if len(infos) < 2 {
		return errors.New("didn't recognize output of 'expinfo'")
	}
	linkInfo := infos[1]
	// Test for correct version in case the API-output changes
	if !strings.HasPrefix(linkInfo, "Virtual Lan/Link Info:") {
		return errors.New("didn't recognize output of 'expinfo'")
	}
	linkLines := strings.Split(linkInfo, "\n")
	if len(linkLines) < 5 {
		return errors.New("didn't recognice output of 'expinfo'")
	}
	nodes := linkLines[3:]

	d.Phys = []string{}
	d.Virt = []string{}
	names := make(map[string]bool)

	for i, node := range nodes {
		if i%2 == 1 {
			continue
		}
		matches := strings.Fields(node)
		if len(matches) != 6 {
			return errors.New("expinfo-output seems to have changed")
		}
		// Convert client-0:0 to client-0
		name := strings.Split(matches[1], ":")[0]
		ip := matches[2]

		fullName := fmt.Sprintf("%s.%s.%s.isi.deterlab.net", name, d.Experiment, d.Project)
		log.Lvl3("Discovered", fullName, "on ip", ip)

		if _, exists := names[fullName]; !exists {
			d.Phys = append(d.Phys, fullName)
			d.Virt = append(d.Virt, ip)
			names[fullName] = true
		}
	}

	log.Lvl2("Physical:", d.Phys)
	log.Lvl2("Internal:", d.Virt)
	return nil
}

// Checks whether host, login and project are defined. If any of them are missing, it will
// ask on the command-line.
// For the login-variable, it will try to set up a connection to d.Host and copy over the
// public key for a more easy communication
func (d *Deterlab) loadAndCheckDeterlabVars() {
	deter := Deterlab{}
	err := onet.ReadTomlConfig(&deter, "deter.toml")
	d.Host, d.Login, d.Project, d.Experiment, d.ProxyAddress, d.MonitorAddress =
		deter.Host, deter.Login, deter.Project, deter.Experiment,
		deter.ProxyAddress, deter.MonitorAddress

	if err != nil {
		log.Lvl1("Couldn't read config-file - asking for default values")
	}

	if d.Host == "" {
		d.Host = readString("Please enter the hostname of deterlab", "users.deterlab.net")
	}

	login, err := user.Current()
	log.ErrFatal(err)
	if d.Login == "" {
		d.Login = readString("Please enter the login-name on "+d.Host, login.Username)
	}

	if d.Project == "" {
		d.Project = readString("Please enter the project on deterlab", "SAFER")
	}

	if d.Experiment == "" {
		d.Experiment = readString("Please enter the Experiment on "+d.Project, "Dissent-CS")
	}

	if d.MonitorAddress == "" {
		d.MonitorAddress = readString("Please enter the Monitor address (where clients will connect)", "users.isi.deterlab.net")
	}
	if d.ProxyAddress == "" {
		d.ProxyAddress = readString("Please enter the proxy redirection address", "localhost")
	}

	onet.WriteTomlConfig(*d, "deter.toml")
}

// Shows a messages and reads in a string, eventually returning a default (dft) string
func readString(msg, dft string) string {
	fmt.Printf("%s [%s]:", msg, dft)

	reader := bufio.NewReader(os.Stdin)
	strnl, _ := reader.ReadString('\n')
	str := strings.TrimSpace(strnl)
	if str == "" {
		return dft
	}
	return str
}

const simulConnectionsConf = `
# This is for the onet-deterlab testbed, which can use up an awful lot of connections

* soft nofile 128000
* hard nofile 128000
`
