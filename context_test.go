package onet

import (
	"testing"

	"path"

	"os"

	"io/ioutil"

	"strings"

	"github.com/dedis/crypto/random"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/stretchr/testify/require"
)

type ContextData struct {
	I int
	S string
}

func TestContextSaveLoad(t *testing.T) {
	contextDataPath = ""
	pub, _ := network.Suite.Point().Pick(nil, random.Stream)
	si := network.NewServerIdentity(pub,
		network.NewAddress(network.Local, "localhost:0"))
	cn := &Conode{
		Router: &network.Router{
			ServerIdentity: si,
		},
	}
	c := newContext(cn, nil, NilServiceID, nil)
	testLoadSave(t, true, c)

	tmp := "/tmp/conode"
	log.ErrFatal(os.RemoveAll(tmp))
	os.Setenv(ENVServiceData, tmp)
	initContextDataPath()
	testLoadSave(t, false, c)
	files, err := ioutil.ReadDir(tmp)
	log.ErrFatal(err)
	require.False(t, files[0].IsDir())
	require.True(t, files[0].Mode().IsRegular())
	require.True(t, strings.HasSuffix(files[0].Name(), ".bin"))
	log.ErrFatal(os.RemoveAll(tmp))
}

func testLoadSave(t *testing.T, first bool, c *Context) {
	file := "test"
	cd := &ContextData{42, "meaning of life"}
	if first {
		require.NotNil(t, c.Save(file, cd))
		network.RegisterPacketType(ContextData{})
	}
	log.ErrFatal(c.Save(file, cd))

	_, err := c.Load(file + "_")
	require.NotNil(t, err)
	cdInt, err := c.Load(file)
	log.ErrFatal(err)
	cd2, ok := cdInt.(*ContextData)
	require.True(t, ok)
	require.Equal(t, cd, cd2)
}

func TestContext_Path(t *testing.T) {
	contextDataPath = ""
	pub, _ := network.Suite.Point().Pick(nil, random.Stream)
	si := network.NewServerIdentity(pub,
		network.NewAddress(network.Local, "localhost:0"))
	cn := &Conode{
		Router: &network.Router{
			ServerIdentity: si,
		},
	}
	c := newContext(cn, nil, NilServiceID, nil)
	base := c.absFilename("test")
	tmp := "/tmp/conode"
	log.ErrFatal(os.RemoveAll(tmp))
	os.Setenv(ENVServiceData, tmp)
	initContextDataPath()
	require.Equal(t, tmp, contextDataPath)
	_, err := os.Stat(tmp)
	log.ErrFatal(err)
	require.Equal(t, path.Join(tmp, base), c.absFilename("test"))
	log.ErrFatal(os.RemoveAll(tmp))
}
