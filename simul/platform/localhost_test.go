package platform

import (
	"os"
	"testing"

	"io/ioutil"

	"github.com/dedis/onet/log"
)

func TestLocal(t *testing.T) {
	l := &Localhost{
		Simulation: "test",
	}
	cur, err := os.Getwd()
	log.ErrFatal(err)
	defer os.Chdir(cur)

	tmp, err := ioutil.TempDir("", "local")
	log.ErrFatal(err)
	log.ErrFatal(os.Chdir(tmp))

	l.Configure(&Config{
		Debug:       0,
		MonitorPort: 10000,
	})
	l.Build("test")
	l.Cleanup()
	l.Deploy(&RunConfig{})
}
