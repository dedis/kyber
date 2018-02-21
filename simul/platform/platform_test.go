package platform

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dedis/onet/log"
)

var testfile = `Machines = 8
RunWait = "33s"
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

	tests := ReadRunFile(tplat, tmpfile.Name())
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
	dt, err := tests[0].GetDuration("runwait")
	if err != nil {
		t.Fatal("unexpected runwait err", err)
	}
	if dt != 33*time.Second {
		t.Fatal("unexpected runwait")
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

	ReadRunFile(tplat, tmpfile.Name())
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
	RunWait  duration
}

func (t *TPlat) Configure(pc *Config)                {}
func (t *TPlat) Build(s string, arg ...string) error { return nil }
func (t *TPlat) Deploy(rc *RunConfig) error          { return nil }
func (t *TPlat) Start(...string) error               { return nil }
func (t *TPlat) Stop() error                         { return nil }
func (t *TPlat) Cleanup() error                      { return nil }
func (t *TPlat) Wait() error                         { return nil }

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

func TestCross(t *testing.T) {
	t.Skip("Test not useful in automated context. Use it manually if you want.")

	log.SetDebugVisible(4)
	dir, err := ioutil.TempDir("", "build")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	hello := []byte(`
package main
func main() {
  println("hello")
}
`)
	err = ioutil.WriteFile(filepath.Join(dir, "hello.go"), hello, 0600)
	if err != nil {
		t.Error(err)
	}

	wd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(wd)

	_, err = Build(".", "out", "386", "freebsd")
	if err != nil {
		t.Error(err)
	}
}
