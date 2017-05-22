package onet

import (
	"testing"

	"path"

	"os"

	"io/ioutil"

	"strings"

	"sync"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/random"
)

type ContextData struct {
	I int
	S string
}

func TestContextSaveLoad(t *testing.T) {
	setContextDataPath("")
	nbr := 10
	c := make([]*Context, nbr)
	for i := range c {
		c[i] = createContext()
	}
	var wg sync.WaitGroup
	wg.Add(nbr)
	testLoadSave(t, true, c[0])
	for i := range c {
		go func(i int) {
			testLoadSave(t, false, c[i])
			wg.Done()
		}(i)
	}
	wg.Wait()

	tmp, err := ioutil.TempDir("", "conode")
	log.ErrFatal(err)
	defer os.RemoveAll(tmp)
	os.Setenv(ENVServiceData, tmp)
	initContextDataPath()
	wg.Add(nbr)
	for i := range c {
		go func(i int) {
			testLoadSave(t, false, c[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	files, err := ioutil.ReadDir(tmp)
	log.ErrFatal(err)
	require.False(t, files[0].IsDir())
	require.True(t, files[0].Mode().IsRegular())
	require.True(t, strings.HasSuffix(files[0].Name(), ".bin"))
}

func testLoadSave(t *testing.T, first bool, c *Context) {
	file := "test"
	cd := &ContextData{42, "meaning of life"}
	if first {
		if c.Save(file, cd) == nil {
			log.Fatal("should not save", log.Stack())
		}
		network.RegisterMessage(ContextData{})
	}
	log.ErrFatal(c.Save(file, cd))

	_, err := c.Load(file + "_")
	if err == nil {
		log.Fatal("this should not exist")
	}
	cdInt, err := c.Load(file)
	log.ErrFatal(err)
	cd2, ok := cdInt.(*ContextData)
	if !ok {
		log.Fatal("contextData should exist")
	}
	if cd.I != cd2.I || cd.S != cd2.S {
		log.Fatal("stored and loaded data should be equal", cd, cd2)
	}
}

func TestContext_Path(t *testing.T) {
	setContextDataPath("")
	c := createContext()
	base := c.absFilename("test")
	tmp, err := ioutil.TempDir("", "conode")
	log.ErrFatal(err)
	defer os.RemoveAll(tmp)
	os.Setenv(ENVServiceData, tmp)
	initContextDataPath()
	require.Equal(t, tmp, contextDataPath)
	_, err = os.Stat(tmp)
	log.ErrFatal(err)
	require.Equal(t, path.Join(tmp, base), c.absFilename("test"))
}

type CD2 struct {
	I int
}

func TestContext_DataAvailable(t *testing.T) {
	setContextDataPath("")
	network.RegisterMessage(CD2{})
	c := createContext()

	require.False(t, c.DataAvailable("test"))
	log.ErrFatal(c.Save("test", &CD2{42}))
	require.True(t, c.DataAvailable("test"))

	tmpdir, err := ioutil.TempDir("", "test")
	log.ErrFatal(err)
	setContextDataPath(tmpdir)
	require.False(t, c.DataAvailable("test"))
	log.ErrFatal(c.Save("test", &CD2{42}))
	require.True(t, c.DataAvailable("test"))
	os.RemoveAll(tmpdir)
}

func createContext() *Context {
	pub, _ := network.S.Point().Pick(nil, random.Stream)
	si := network.NewServerIdentity(pub,
		network.NewAddress(network.Local, "localhost:0"))
	cn := &Server{
		Router: &network.Router{
			ServerIdentity: si,
		},
	}
	return newContext(cn, nil, NilServiceID, nil)
}
