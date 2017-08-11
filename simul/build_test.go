package simul

import (
	"strconv"
	"testing"

	"github.com/dedis/onet/simul/platform"
)

func TestBuild(t *testing.T) {
}

func TestDepth(t *testing.T) {
	testStruct := []struct{ BF, depth, hosts int }{
		{1, 1, 2},
		{2, 1, 3},
		{3, 1, 4},
		{3, 2, 13},
		{4, 1, 5},
		{4, 2, 21},
		{5, 1, 6},
		{5, 2, 31},
		{5, 3, 156},
	}
	for _, s := range testStruct {
		rc := platform.NewRunConfig()
		rc.Put("bf", strconv.Itoa(s.BF))
		rc.Put("depth", strconv.Itoa(s.depth))
		CheckHosts(rc)
		hosts, _ := rc.GetInt("hosts")
		if hosts != s.hosts {
			t.Fatal(s, "gave hosts:", hosts)
		}
		rc.Put("bf", "0")
		CheckHosts(rc)
		bf, _ := rc.GetInt("bf")
		if bf != s.BF {
			t.Fatal(s, "gave BF:", bf)
		}
		rc.Put("depth", "0")
		CheckHosts(rc)
		depth, _ := rc.GetInt("depth")
		if depth != s.depth {
			t.Fatal(s, "gave depth:", bf)
		}
	}
}
