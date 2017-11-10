package onet

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet/log"
)

// WriteTomlConfig write  any structure to a toml-file
// Takes a filename and an optional directory-name.
func WriteTomlConfig(conf interface{}, filename string, dirOpt ...string) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(conf); err != nil {
		log.Fatal(err)
	}
	err := ioutil.WriteFile(getFullName(filename, dirOpt...), buf.Bytes(), 0660)
	if err != nil {
		log.Fatal(err)
	}
}

// ReadTomlConfig read any structure from a toml-file
// Takes a filename and an optional directory-name
func ReadTomlConfig(conf interface{}, filename string, dirOpt ...string) error {
	buf, err := ioutil.ReadFile(getFullName(filename, dirOpt...))
	if err != nil {
		pwd, _ := os.Getwd()
		log.Lvl1("Didn't find", filename, "in", pwd)
		return err
	}

	_, err = toml.Decode(string(buf), conf)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

/*
 * Gets filename and dirname
 *
 * special cases:
 * - filename only
 * - filename in relative path
 * - filename in absolute path
 * - filename and additional path
 */
func getFullName(filename string, dirOpt ...string) string {
	dir := filepath.Dir(filename)
	if len(dirOpt) > 0 {
		dir = dirOpt[0]
	} else {
		if dir == "" {
			dir = "."
		}
	}
	return dir + "/" + filepath.Base(filename)
}

type collectedErrors struct {
	s string
	e error
}

func collectErrors(format string, m []collectedErrors) error {
	var errStr string
	for _, e := range m {
		errStr += fmt.Sprintf(format, e.s, e.e)
	}
	if errStr == "" {
		return nil
	}
	return errors.New(errStr)
}
