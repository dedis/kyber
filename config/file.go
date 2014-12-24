package config

import (
	"os"
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/dedis/crypto/util"
)


// XXX it wouldn't be hard to parameterize the file format parser
// rather than binding it to TOML.
// Perhaps define an Encode/Decode interface
// and create sub-packages for different compatible formats...


// Cryptographic configuration file
type File struct {
	dirName string			// Configuration directory
	data interface{}		// In-memory configuration state
	keys map[string]KeyPair		// Key-pairs indexed by ciphersuite
}

func (f *File) init(appName string) error {

	// XXX os-specific stuff
	homedir := os.Getenv("HOME")
	confdir := homedir + "/." + appName

	// Create the config directory if it doesn't already exist
	if err := os.MkdirAll(confdir, 0700); err != nil {
		return err
	}

	// Sanity-check the config directory permission bits for security
	if fi,err := os.Stat(confdir); err != nil || (fi.Mode() & 0077) != 0 {
		return errors.New("Directory "+confdir+
				" has insecure permissions")
	}

	f.dirName = confdir
	f.keys = make(map[string]KeyPair)
	return nil
}

// Load a TOML-format config file for an application with the given name.
// The provided configData object will contain the loaded config data;
// its reflective Go structure defines the TOML format it expects.
func (f *File) Load(appName string, configData interface{}) error {

	// Create/check the config directory
	if err := f.init(appName); err != nil {
		return err
	}

	// Read the config file if it exists
	filename := f.dirName+"/config"
	_,err := toml.DecodeFile(filename, configData)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	f.data = configData

	return nil
}

// Re-save the (modified) configData loaded earlier with Load().
// Takes precautions to replace the old config file atomically
// to avoid config file corruption due to write errors or races.
func (f *File) Save() error {

	// Write the new config file
	filename := f.dirName+"/config"
	r := util.Replacer{}
	if err := r.Open(filename); err != nil {
		return err
	}
	defer r.Abort()

	// Encode the config
	enc := toml.NewEncoder(r.File)
	if err := enc.Encode(f.data); err != nil {
		return err
	}

	// Commit the new config
	if err := r.Commit(); err != nil {
		return err
	} 

	return nil
}

