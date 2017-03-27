// Package platform contains interface and implementation to run onet code
// amongst multiple platforms. Such implementations include Localhost (run your
// test locally) and Deterlab (similar to emulab).
package platform

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"sync"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet/log"
)

// Platform interface that has to be implemented to add another simulation-
// platform.
type Platform interface {
	// Does the initial configuration of all structures needed for the platform
	Configure(*Config)
	// Build builds all necessary binaries
	Build(build string, arg ...string) error
	// Makes sure that there is no part of the application still running
	Cleanup() error
	// Copies the binaries to the appropriate directory/machines, together with
	// the necessary configuration. RunConfig is a simple string that should
	// be copied as 'app.toml' to the directory where the app resides
	Deploy(*RunConfig) error
	// Starts the application and returns - non-blocking!
	Start(args ...string) error
	// Waits for the application to quit
	Wait() error
}

// Config is passed to Platform.Config and prepares the platform for
// specific system-wide configurations
type Config struct {
	MonitorPort int
	Debug       int
}

var deterlab = "deterlab"
var localhost = "localhost"
var mininet = "mininet"

// NewPlatform returns the appropriate platform
// [deterlab,localhost]
func NewPlatform(t string) Platform {
	var p Platform
	switch t {
	case deterlab:
		p = &Deterlab{}
	case localhost:
		p = &Localhost{}
	case mininet:
		p = &MiniNet{}
	}
	return p
}

// ReadRunFile reads from a configuration-file for a run. The configuration-file has the
// following syntax:
// Name1 = value1
// Name2 = value2
// [empty line]
// n1, n2, n3, n4
// v11, v12, v13, v14
// v21, v22, v23, v24
//
// The Name1...Namen are global configuration-options.
// n1..nn are configuration-options for one run
// Both the global and the run-configuration are copied to both
// the platform and the app-configuration.
func ReadRunFile(p Platform, filename string) []*RunConfig {
	var runconfigs []*RunConfig
	masterConfig := NewRunConfig()
	log.Lvl3("Reading file", filename)

	file, err := os.Open(filename)
	defer func() {
		if err := file.Close(); err != nil {
			log.Error("Couldn' close", file.Name())
		}
	}()
	if err != nil {
		log.Fatal("Couldn't open file", file, err)
	}

	// Decoding of the first part of the run config file
	// where the config wont change for the whole set of the simulation's tests
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		log.Lvl3("Decoding", text)
		// end of the first part
		if text == "" {
			break
		}
		if text[0] == '#' {
			continue
		}

		// checking if format is good
		vals := strings.Split(text, "=")
		if len(vals) != 2 {
			log.Fatal("Simulation file:", filename, " is not properly formatted ( key = value )")
		}
		// fill in the general config
		masterConfig.Put(strings.TrimSpace(vals[0]), strings.TrimSpace(vals[1]))
		// also put it in platform
		if _, err := toml.Decode(text, p); err != nil {
			log.Error("Error decoding", text)
		}
		log.Lvlf5("Platform is now %+v", p)
	}

	for scanner.Scan() {
		if scanner.Text() != "" {
			break
		}
	}
	args := strings.Split(scanner.Text(), ",")
	for scanner.Scan() {
		rc := masterConfig.Clone()
		// put each individual test configs
		for i, value := range strings.Split(scanner.Text(), ",") {
			rc.Put(strings.TrimSpace(args[i]), strings.TrimSpace(value))
		}
		runconfigs = append(runconfigs, rc)
	}

	return runconfigs
}

// RunConfig is a struct that represent the configuration to apply for one "test"
// Note: a "simulation" is a set of "tests"
type RunConfig struct {
	fields map[string]string
	sync.RWMutex
}

// NewRunConfig returns an initialised config to be used for reading
// in runconfig-files
func NewRunConfig() *RunConfig {
	rc := new(RunConfig)
	rc.fields = make(map[string]string)
	return rc
}

// One problem for now is RunConfig read also the ' " ' char (34 ASCII)
// and thus when doing Get(), also return the value enclosed by ' " '
// One fix is to each time we Get(), automatically delete those chars
var replacer = strings.NewReplacer("\"", "", "'", "")

// Get returns the associated value of the field in the config
func (r *RunConfig) Get(field string) string {
	r.RLock()
	defer r.RUnlock()
	return replacer.Replace(r.fields[strings.ToLower(field)])
}

// Delete a field from the runconfig (delete for example Simulation which we
// dont care in the final csv)
func (r *RunConfig) Delete(field string) {
	r.Lock()
	defer r.Unlock()
	delete(r.fields, field)
}

// GetInt returns the integer of the field, or error if not defined
func (r *RunConfig) GetInt(field string) (int, error) {
	val := r.Get(field)
	if val == "" {
		return 0, errors.New("Didn't find " + field)
	}
	ret, err := strconv.Atoi(val)
	return ret, err
}

// Put inserts a new field - value relationship
func (r *RunConfig) Put(field, value string) {
	r.Lock()
	defer r.Unlock()
	r.fields[strings.ToLower(field)] = value
}

// Toml returns this config as bytes in a Toml format
func (r *RunConfig) Toml() []byte {
	r.RLock()
	defer r.RUnlock()
	var buf bytes.Buffer
	for k, v := range r.fields {
		fmt.Fprintf(&buf, "%s = %s\n", k, v)
	}
	return buf.Bytes()
}

// Map returns this config as a Map
func (r *RunConfig) Map() map[string]string {
	r.RLock()
	defer r.RUnlock()
	tomap := make(map[string]string)
	for k := range r.fields {
		tomap[k] = r.Get(k)
	}
	return tomap
}

// Clone this runconfig so it has all fields-value relationship already present
func (r *RunConfig) Clone() *RunConfig {
	r.RLock()
	defer r.RUnlock()
	rc := NewRunConfig()
	for k, v := range r.fields {
		rc.fields[k] = v
	}
	return rc
}

// String prints out the current status-line
func (r *RunConfig) String() string {
	r.RLock()
	defer r.RUnlock()
	fields := []string{"simulation", "servers", "hosts", "bf", "depth", "rounds"}
	var ret string
	for _, f := range fields {
		v := r.Get(f)
		if v != "" {
			ret = fmt.Sprintf("%s%s:%s ", ret, f, v)
		}
	}
	return ret
}
