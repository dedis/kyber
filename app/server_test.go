package app

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/dedis/kyber/suites"
	"github.com/dedis/onet/log"
)

func TestInteractiveConfig(t *testing.T) {
	tmp, err := ioutil.TempDir("", "conode")
	log.ErrFatal(err)
	log.OutputToBuf()
	setInput("127.0.0.1:2000\nConode1\n" + tmp)
	InteractiveConfig(suites.MustFind("Ed25519"), tmp+"/config.bin")
	log.ErrFatal(os.RemoveAll(tmp))
	log.OutputToOs()
}
