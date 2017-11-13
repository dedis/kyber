package app

import (
	"testing"

	"io/ioutil"
	"os"

	"github.com/dedis/onet/log"
)

func TestInteractiveConfig(t *testing.T) {
	tmp, err := ioutil.TempDir("", "cosi")
	log.ErrFatal(err)
	log.OutputToBuf()
	setInput("127.0.0.1:2000\nCosi1\n" + tmp)
	InteractiveConfig(tmp + "/config.bin")
	log.ErrFatal(os.RemoveAll(tmp))
	log.OutputToOs()
}
