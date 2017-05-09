package onet

import (
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dedis/onet/log"
)

func TestSimulationBF(t *testing.T) {
	sc, _, err := createBFTree(7, 2, []string{"test1", "test2"})
	if err != nil {
		t.Fatal(err)
	}
	addresses := []string{
		"test1:2000",
		"test2:2000",
		"test1:2002",
		"test2:2002",
		"test1:2004",
		"test2:2004",
		"test1:2006",
	}

	for i, a := range sc.Roster.List {
		if !strings.Contains(string(a.Address), addresses[i]) {
			t.Fatal("Address", string(a.Address), "should be", addresses[i])
		}
	}
	if !sc.Tree.IsBinary(sc.Tree.Root) {
		t.Fatal("Created tree is not binary")
	}

	sc, _, err = createBFTree(13, 3, []string{"test1", "test2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Tree.Root.Children) != 3 {
		t.Fatal("Branching-factor 3 tree has not 3 children")
	}
	if !sc.Tree.IsNary(sc.Tree.Root, 3) {
		t.Fatal("Created tree is not binary")
	}
}

func TestSimulationBigTree(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	for i := uint(4); i < 8; i++ {
		_, _, err := createBFTree(1<<i-1, 2, []string{"test1", "test2"})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSimulationLoadSave(t *testing.T) {
	sc, _, err := createBFTree(7, 2, []string{"127.0.0.1", "127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := ioutil.TempDir("", "example")
	log.ErrFatal(err)
	defer os.RemoveAll(dir)
	sc.Save(dir)
	sc2, err := LoadSimulationConfig(dir, sc.Roster.List[0].Address.NetworkAddress())
	if err != nil {
		t.Fatal(err)
	}
	if !sc2[0].Tree.ID.Equal(sc.Tree.ID) {
		t.Fatal("Tree-id is not correct")
	}
	closeAll(sc2)
}

func TestSimulationMultipleInstances(t *testing.T) {
	sc, _, err := createBFTree(7, 2, []string{"127.0.0.1", "127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := ioutil.TempDir("", "example")
	log.ErrFatal(err)
	defer os.RemoveAll(dir)
	sc.Save(dir)
	sc2, err := LoadSimulationConfig(dir, sc.Roster.List[0].Address.Host())
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(sc2)
	if len(sc2) != 4 {
		t.Fatal("We should have 4 local1-hosts but have", len(sc2))
	}
	if sc2[0].Server.ServerIdentity.ID.Equal(sc2[1].Server.ServerIdentity.ID) {
		t.Fatal("Hosts are not copies")
	}
}

func closeAll(scs []*SimulationConfig) {
	for _, s := range scs {
		if err := s.Server.Close(); err != nil {
			log.Error("Error closing host ", s.Server.ServerIdentity)
		}

		for s.Server.Router.Listening() {
			log.Lvl2("Sleeping while waiting for router to be closed")
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func createBFTree(hosts, bf int, addresses []string) (*SimulationConfig, *SimulationBFTree, error) {
	sc := &SimulationConfig{}
	sb := &SimulationBFTree{
		Hosts: hosts,
		BF:    bf,
	}
	sb.CreateRoster(sc, addresses, 2000)
	if len(sc.Roster.List) != hosts {
		return nil, nil, errors.New("Didn't get correct number of entities")
	}
	err := sb.CreateTree(sc)
	if err != nil {
		return nil, nil, err
	}
	if !sc.Tree.IsNary(sc.Tree.Root, bf) {
		return nil, nil, errors.New("Tree isn't " + strconv.Itoa(bf) + "-ary")
	}

	return sc, sb, nil
}
