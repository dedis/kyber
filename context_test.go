package onet

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	bolt "github.com/coreos/bbolt"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/stretchr/testify/require"
)

type ContextData struct {
	I int
	S string
}

func TestContextSaveLoad(t *testing.T) {
	tmp, err := ioutil.TempDir("", "conode")
	defer os.RemoveAll(tmp)
	os.Setenv("CONODE_SERVICE_PATH", tmp)
	initContextDataPath()

	nbr := 10
	c := make([]*Context, nbr)
	for i := range c {
		c[i] = createContext(t)
	}

	testSaveFailure(t, c[0])

	var wg sync.WaitGroup
	wg.Add(nbr)
	for i := range c {
		go func(i int) {
			testLoadSave(t, c[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	files, err := ioutil.ReadDir(tmp)
	log.ErrFatal(err)
	require.False(t, files[0].IsDir())
	require.True(t, files[0].Mode().IsRegular())
	require.True(t, strings.HasSuffix(files[0].Name(), ".db"))
	setContextDataPath("")
}

func testLoadSave(t *testing.T, c *Context) {
	key := "test"
	cd := &ContextData{42, "meaning of life"}
	network.RegisterMessage(ContextData{})
	require.Nil(t, c.Save(key, cd))

	msg, err := c.Load(key + "_")
	if err != nil || msg != nil {
		log.Fatal("this should not exist")
	}
	cdInt, err := c.Load(key)
	require.Nil(t, err)
	cd2, ok := cdInt.(*ContextData)
	if !ok {
		log.Fatal("contextData should exist")
	}
	if cd.I != cd2.I || cd.S != cd2.S {
		log.Fatal("stored and loaded data should be equal", cd, cd2)
	}
}

func testSaveFailure(t *testing.T, c *Context) {
	key := "test"
	cd := &ContextData{42, "meaning of life"}
	// should fail because ContextData is not registered
	if c.Save(key, cd) == nil {
		log.Fatal("Save should fail")
	}
}

func TestContext_GetAdditionalBucket(t *testing.T) {
	tmp, err := ioutil.TempDir("", "conode")
	log.ErrFatal(err)
	defer os.RemoveAll(tmp)
	os.Setenv("CONODE_SERVICE_PATH", tmp)
	initContextDataPath()
	c := createContext(t)
	db, name := c.GetAdditionalBucket("new")
	require.NotNil(t, db)
	require.Equal(t, "testServicenew", name)
	// Need to accept a second run with an existing bucket
	db, name = c.GetAdditionalBucket("new")
	require.NotNil(t, db)
	require.Equal(t, "testServicenew", name)
}

func TestContext_Path(t *testing.T) {
	setContextDataPath("")
	c := createContext(t)
	pub, _ := c.ServerIdentity().Public.MarshalBinary()
	dbPath := path.Join("", fmt.Sprintf("%x.db", pub))
	_, err := os.Stat(dbPath)
	log.ErrFatal(err)
	os.Remove(dbPath)

	tmp, err := ioutil.TempDir("", "conode")
	log.ErrFatal(err)
	defer os.RemoveAll(tmp)
	os.Setenv("CONODE_SERVICE_PATH", tmp)
	initContextDataPath()
	c = createContext(t)
	require.Equal(t, tmp, contextDataPath)
	_, err = os.Stat(tmp)
	log.ErrFatal(err)
	pub, _ = c.ServerIdentity().Public.MarshalBinary()
	_, err = os.Stat(path.Join(tmp, fmt.Sprintf("%x.db", pub)))
	log.ErrFatal(err)
}

// createContext creates the minimum number of things required for the test
func createContext(t *testing.T) *Context {
	kp := key.NewKeyPair(tSuite)
	si := network.NewServerIdentity(kp.Public,
		network.NewAddress(network.Local, "localhost:0"))
	cn := &Server{
		Router: &network.Router{
			ServerIdentity: si,
		},
	}

	name := "testService"
	RegisterNewService(name, func(c *Context) (Service, error) {
		return nil, nil
	})

	db, err := openDb(cn.dbFileName())
	require.Nil(t, err)

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(name))
		return err
	})
	require.Nil(t, err)

	sm := &serviceManager{
		server: cn,
		db:     db,
	}
	return newContext(cn, nil, ServiceFactory.ServiceID(name), sm)
}
