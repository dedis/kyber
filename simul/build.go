package simul

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"errors"
	"math"
	"time"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/monitor"
	"github.com/dedis/onet/simul/platform"
)

// Configuration-variables
var deployP platform.Platform

var platformDst = "localhost"
var nobuild = false
var clean = true
var build = ""
var machines = 3
var monitorPort = monitor.DefaultSinkPort
var simRange = ""
var race = false
var runWait = 180
var experimentWait = 0

func init() {
	flag.StringVar(&platformDst, "platform", platformDst, "platform to deploy to [deterlab,localhost]")
	flag.BoolVar(&nobuild, "nobuild", false, "Don't rebuild all helpers")
	flag.BoolVar(&clean, "clean", false, "Only clean platform")
	flag.StringVar(&build, "build", "", "List of packages to build")
	flag.BoolVar(&race, "race", false, "Build with go's race detection enabled (doesn't work on all platforms)")
	flag.IntVar(&machines, "machines", machines, "Number of machines on Deterlab")
	flag.IntVar(&monitorPort, "mport", monitorPort, "Port-number for monitor")
	flag.StringVar(&simRange, "range", simRange, "Range of simulations to run. 0: or 3:4 or :4")
	flag.IntVar(&runWait, "runwait", runWait, "How long to wait for each simulation to finish - overwrites .toml-value")
	flag.IntVar(&experimentWait, "experimentwait", experimentWait, "How long to wait for the whole experiment to finish")
	log.RegisterFlags()
}

// Reads in the platform that we want to use and prepares for the tests
func startBuild() {
	flag.Parse()
	deployP = platform.NewPlatform(platformDst)
	if deployP == nil {
		log.Fatal("Platform not recognized.", platformDst)
	}
	log.Lvl1("Deploying to", platformDst)

	simulations := flag.Args()
	if len(simulations) == 0 {
		log.Fatal("Please give a simulation to run")
	}

	for _, simulation := range simulations {
		runconfigs := platform.ReadRunFile(deployP, simulation)

		if len(runconfigs) == 0 {
			log.Fatal("No tests found in", simulation)
		}
		deployP.Configure(&platform.Config{
			MonitorPort: monitorPort,
			Debug:       log.DebugVisible(),
		})

		if clean {
			err := deployP.Deploy(runconfigs[0])
			if err != nil {
				log.Fatal("Couldn't deploy:", err)
			}
			if err := deployP.Cleanup(); err != nil {
				log.Error("Couldn't cleanup correctly:", err)
			}
		} else {
			logname := strings.Replace(filepath.Base(simulation), ".toml", "", 1)
			testsDone := make(chan bool)
			timeout := getExperimentWait(runconfigs)
			go func() {
				RunTests(logname, runconfigs)
				testsDone <- true
			}()
			select {
			case <-testsDone:
				log.Lvl3("Done with test", simulation)
			case <-time.After(time.Second * time.Duration(timeout)):
				log.Fatal("Test failed to finish in", timeout, "seconds")
			}
		}
	}
}

// RunTests the given tests and puts the output into the
// given file name. It outputs RunStats in a CSV format.
func RunTests(name string, runconfigs []*platform.RunConfig) {

	if nobuild == false {
		if race {
			if err := deployP.Build(build, "-race"); err != nil {
				log.Error("Couln't finish build without errors:",
					err)
			}
		} else {
			if err := deployP.Build(build); err != nil {
				log.Error("Couln't finish build without errors:",
					err)
			}
		}
	}

	mkTestDir()
	rs := make([]*monitor.Stats, len(runconfigs))
	// Try 10 times to run the test
	nTimes := 10
	stopOnSuccess := true
	var f *os.File
	args := os.O_CREATE | os.O_RDWR | os.O_TRUNC
	// If a range is given, we only append
	if simRange != "" {
		args = os.O_CREATE | os.O_RDWR | os.O_APPEND
	}
	f, err := os.OpenFile(testFile(name), args, 0660)
	if err != nil {
		log.Fatal("error opening test file:", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Error("Couln't close", f.Name())
		}
	}()
	err = f.Sync()
	if err != nil {
		log.Fatal("error syncing test file:", err)
	}

	start, stop := getStartStop(len(runconfigs))
	for i, rc := range runconfigs {
		// Implement a simple range-argument that will skip checks not in range
		if i < start || i > stop {
			log.Lvl2("Skipping", rc, "because of range")
			continue
		}
		// Waiting for the document-branch to be merged, then uncomment this
		//log.Lvl1("Starting run with parameters -", t.String())

		// run test t nTimes times
		// take the average of all successful runs
		runs := make([]*monitor.Stats, 0, nTimes)
		for r := 0; r < nTimes; r++ {
			stats, err := RunTest(rc)
			if err != nil {
				log.Error("Error running test, trying again:", err)
				continue
			}

			runs = append(runs, stats)
			if stopOnSuccess {
				break
			}
		}

		if len(runs) == 0 {
			log.Lvl1("unable to get any data for test:", rc)
			continue
		}

		s := monitor.AverageStats(runs)
		if i == 0 {
			s.WriteHeader(f)
		}
		rs[i] = s
		rs[i].WriteValues(f)
		err = f.Sync()
		if err != nil {
			log.Fatal("error syncing data to test file:", err)
		}
	}
}

// RunTest a single test - takes a test-file as a string that will be copied
// to the deterlab-server
func RunTest(rc *platform.RunConfig) (*monitor.Stats, error) {
	CheckHosts(rc)
	rc.Delete("simulation")
	rs := monitor.NewStats(rc.Map(), "hosts", "bf")
	monitor := monitor.NewMonitor(rs)

	if err := deployP.Deploy(rc); err != nil {
		log.Error(err)
		return rs, err
	}

	monitor.SinkPort = monitorPort
	if err := deployP.Cleanup(); err != nil {
		log.Error(err)
		return rs, err
	}
	monitor.SinkPort = monitorPort
	done := make(chan error)
	go func() {
		done <- monitor.Listen()
	}()
	// Start monitor before so ssh tunnel can connect to the monitor
	// in case of deterlab.
	err := deployP.Start()
	if err != nil {
		log.Error(err)
		return rs, err
	}

	go func() {
		var err error
		if err = deployP.Wait(); err != nil {
			log.Lvl3("Test failed:", err)
			if err := deployP.Cleanup(); err != nil {
				log.Lvl3("Couldn't cleanup platform:", err)
			}
			monitor.Stop()
		}
		log.Lvl3("Test complete:", rs)
	}()

	timeOut := getRunWait(rc)
	// can timeout the command if it takes too long
	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return rs, nil
	case <-time.After(time.Second * time.Duration(timeOut)):
		monitor.Stop()
		return rs, errors.New("Simulation timeout")
	}
}

// CheckHosts verifies that there is either a 'Hosts' or a 'Depth/BF'
// -parameter in the Runconfig
func CheckHosts(rc *platform.RunConfig) {
	hosts, _ := rc.GetInt("hosts")
	bf, _ := rc.GetInt("bf")
	depth, _ := rc.GetInt("depth")
	if hosts == 0 {
		if depth == 0 || bf == 0 {
			log.Fatal("No Hosts and no Depth or BF given - stopping")
		}
		hosts = calcHosts(bf, depth)
		rc.Put("hosts", strconv.Itoa(hosts))
	}
	if bf == 0 {
		if depth == 0 || hosts == 0 {
			log.Fatal("No BF and no Depth or hosts given - stopping")
		}
		bf = 2
		for calcHosts(bf, depth) < hosts {
			bf++
		}
		rc.Put("bf", strconv.Itoa(bf))
	}
	if depth == 0 {
		depth = 1
		for calcHosts(bf, depth) < hosts {
			depth++
		}
		rc.Put("depth", strconv.Itoa(depth))
	}
}

// Geometric sum to count the total number of nodes:
// Root-node: 1
// 1st level: bf (branching-factor)*/
// 2nd level: bf^2 (each child has bf children)
// 3rd level: bf^3
// So total: sum(level=0..depth)(bf^level)
func calcHosts(bf, depth int) int {
	return int((1 - math.Pow(float64(bf), float64(depth+1))) /
		float64(1-bf))
}

type runFile struct {
	Machines int
	Args     string
	Runs     string
}

func mkTestDir() {
	err := os.MkdirAll("test_data/", 0777)
	if err != nil {
		log.Fatal("failed to make test directory")
	}
}

func testFile(name string) string {
	return "test_data/" + name + ".csv"
}

// returns a tuple of start and stop configurations to run
func getStartStop(rcs int) (int, int) {
	ssStr := strings.Split(simRange, ":")
	start, err := strconv.Atoi(ssStr[0])
	stop := rcs - 1
	if err == nil {
		stop = start
		if len(ssStr) > 1 {
			stop, err = strconv.Atoi(ssStr[1])
			if err != nil {
				stop = rcs
			}
		}
	}
	log.Lvl2("Range is", start, ":", stop)
	return start, stop
}

// getRunWait returns either the command-line value or the value from the runconfig
// file
func getRunWait(rc *platform.RunConfig) int {
	rcWait, err := rc.GetInt("runwait")
	if err == nil {
		return rcWait
	}
	return runWait
}

// getExperimentWait returns
// 1. the command-line value
// 2. the value from runconfig
// 3. #runconfigs * runWait
func getExperimentWait(rcs []*platform.RunConfig) int {
	if experimentWait > 0 {
		return experimentWait
	}
	rcExp, err := rcs[0].GetInt("experimentwait")
	if err == nil {
		return rcExp
	}
	wait := 0
	for _, rc := range rcs {
		wait += getRunWait(rc)
	}
	return wait
}
