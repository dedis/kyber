package platform

import (
	"testing"

	"strconv"

	"fmt"

	"io/ioutil"

	"path/filepath"

	"os"
	"path"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v2/log"
)

func TestMiniNet_getHostList(t *testing.T) {
	testVector := []struct {
		ServersInFile int // In 'server_list' file
		Servers       int
		Hosts         int
		HostsSlice    []string
		List          string
	}{
		{1, 1, 1,
			[]string{"10.1.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\n"},
		{3, 1, 1,
			[]string{"10.1.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\n"},
		{1, 1, 2,
			[]string{"10.1.0.2", "10.1.0.3"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 2\n"},
		{2, 2, 1,
			[]string{"10.1.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\n"},
		{3, 2, 1,
			[]string{"10.1.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\n"},
		{2, 2, 2,
			[]string{"10.1.0.2", "10.2.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\nlocal2 10.2.0.0/16 1\n"},
		{2, 2, 3,
			[]string{"10.1.0.2", "10.2.0.2", "10.1.0.3"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 2\nlocal2 10.2.0.0/16 1\n"},
		{3, 3, 1,
			[]string{"10.1.0.2"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 1\n"},
		{3, 3, 4,
			[]string{"10.1.0.2", "10.2.0.2", "10.3.0.2",
				"10.1.0.3"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 2\nlocal2 10.2.0.0/16 1\nlocal3 10.3.0.0/16 1\n"},
		{4, 3, 4,
			[]string{"10.1.0.2", "10.2.0.2", "10.3.0.2",
				"10.1.0.3"},
			"cosi 0 0\n0 false false\n\nlocal1 10.1.0.0/16 2\nlocal2 10.2.0.0/16 1\nlocal3 10.3.0.0/16 1\n"},
	}
	for _, tv := range testVector {
		mn := &MiniNet{Simulation: "cosi"}
		for i := 1; i <= tv.ServersInFile; i++ {
			mn.HostIPs = append(mn.HostIPs, fmt.Sprintf("local%d", i))
		}

		rc := makeRunConfig(tv.Servers, tv.Hosts)
		h, l, err := mn.getHostList(rc)
		log.ErrFatal(err)
		errStr := fmt.Sprintf("ServersInFile: %d - Servers: %d - Hosts: %d",
			tv.ServersInFile, tv.Servers, tv.Hosts)
		assert.Equal(t, tv.HostsSlice, h, errStr)
		assert.Equal(t, tv.List, l, errStr)
	}
}

func TestMiniNet_getHostList2(t *testing.T) {
	mn := &MiniNet{HostIPs: []string{"local1"}}
	h, _, err := mn.getHostList(makeRunConfig(1, 256))
	log.ErrFatal(err)
	assert.Equal(t, "10.1.0.254", h[252])
	assert.Equal(t, "10.1.0.255", h[253])
	assert.Equal(t, "10.1.1.0", h[254])
	assert.Equal(t, "10.1.1.1", h[255])
}

func TestMiniNet_parseServers(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "server_list")
	log.ErrFatal(err)
	tmpfile.WriteString("192.168.0.1\n")
	tmpfile.WriteString("192.168.0.2\n")
	tmpfile.Close()
	os.Rename(tmpfile.Name(), path.Join(filepath.Dir(tmpfile.Name()), "server_list"))
	m := MiniNet{wd: filepath.Dir(tmpfile.Name())}
	err = m.parseServers()
	log.ErrFatal(err)
	assert.Equal(t, 2, len(m.HostIPs))
}

func makeRunConfig(servers, hosts int) *RunConfig {
	return &RunConfig{fields: map[string]string{
		"servers": strconv.Itoa(servers),
		"hosts":   strconv.Itoa(hosts),
	}}
}
