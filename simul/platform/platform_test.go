package platform_test

import (
	"io/ioutil"
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/platform"
)

var testfile = `Machines = 8
App = "sign"

Ppm, Rounds
2, 30
4, 30`

var testfile2 = `Machines = 8
App = "sign"`

func TestReadRunfile(t *testing.T) {
	tplat := &TPlat{}

	tmpfile, err := ioutil.TempFile("", "testrun.toml")
	log.ErrFatal(err)
	_, err = tmpfile.Write([]byte(testfile))
	if err != nil {
		log.Fatal("Couldn't write to tmp-file:", err)
	}
	tmpfile.Close()

	tests := platform.ReadRunFile(tplat, tmpfile.Name())
	log.Lvl2(tplat)
	log.Lvlf2("%+v\n", tests[0])
	if tplat.App != "sign" {
		log.Fatal("App should be 'sign'")
	}
	if len(tests) != 2 {
		log.Fatal("There should be 2 tests")
	}
	if tests[0].Get("machines") != "8" {
		log.Fatal("Machines = 8 has not been copied into RunConfig")
	}
}

func TestReadRunfile2(t *testing.T) {
	tplat := &TPlat{}

	tmpfile, err := ioutil.TempFile("", "testrun.toml")
	log.ErrFatal(err)
	_, err = tmpfile.Write([]byte(testfile2))
	if err != nil {
		log.Fatal("Couldn't write to tmp-file:", err)
	}
	tmpfile.Close()

	platform.ReadRunFile(tplat, tmpfile.Name())
	if tplat.App != "sign" {
		log.Fatal("App should be 'sign'")
	}
	if tplat.Machines != 8 {
		log.Fatal("Machines should be 8")
	}
}

type TPlat struct {
	App      string
	Machines int
}

func (t *TPlat) Configure(pc *platform.Config)       {}
func (t *TPlat) Build(s string, arg ...string) error { return nil }
func (t *TPlat) Deploy(rc *platform.RunConfig) error { return nil }
func (t *TPlat) Start(...string) error               { return nil }
func (t *TPlat) Stop() error                         { return nil }
func (t *TPlat) Cleanup() error                      { return nil }
func (t *TPlat) Wait() error                         { return nil }
