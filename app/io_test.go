package app

import (
	"bufio"
	"bytes"
	"testing"

	"io/ioutil"

	"os"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInput(t *testing.T) {
	setInput("Y")
	assert.Equal(t, "Y", Input("def", "Question"))
	assert.Equal(t, "Question [def]: ", getOutput())
	setInput("")
	assert.Equal(t, "def", Input("def", "Question"))
	setInput("1\n2")
	assert.Equal(t, "1", Input("", "Question1"))
	assert.Equal(t, "2", Input("1", "Question2"))
}

func TestInputYN(t *testing.T) {
	setInput("")
	assert.True(t, InputYN(true))
	setInput("")
	assert.False(t, InputYN(false, "Are you sure?"))
	assert.Equal(t, "Are you sure? [Ny]: ", getOutput())
	setInput("")
	assert.True(t, InputYN(true, "Are you sure?"))
	assert.Equal(t, "Are you sure? [Yn]: ", getOutput(), "one")
}

func TestCopy(t *testing.T) {
	tmp, err := ioutil.TempFile("", "copy")
	log.ErrFatal(err)
	_, err = tmp.Write([]byte{3, 1, 4, 5, 9, 2, 6})
	log.ErrFatal(err)
	log.ErrFatal(tmp.Close())
	nsrc := tmp.Name()
	ndst := nsrc + "1"
	log.ErrFatal(Copy(ndst, nsrc))
	stat, err := os.Stat(ndst)
	log.ErrFatal(err)
	require.Equal(t, int64(7), stat.Size())
	log.ErrFatal(os.Remove(nsrc))
	log.ErrFatal(os.Remove(ndst))
}

func setInput(s string) {
	// Flush output
	getOutput()
	in = bufio.NewReader(bytes.NewReader([]byte(s + "\n")))
}

func getOutput() string {
	out := o.Bytes()
	o.Reset()
	return string(out)
}
