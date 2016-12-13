package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	OutputToBuf()
	MainTest(m)
}

func TestInfo(t *testing.T) {
	SetDebugVisible(FormatPython)
	Info("Python")
	assert.True(t, ContainsStdOut("[+] Python\n"))
	SetDebugVisible(FormatNone)
	Info("None")
	assert.True(t, ContainsStdOut("None\n"))
	Info("None", "Python")
	assert.True(t, ContainsStdOut("None Python\n"))
	SetDebugVisible(1)
}

func TestLvl(t *testing.T) {
	SetDebugVisible(1)
	Info("TestLvl")
	assert.True(t, ContainsStdOut("I : (                             log.TestLvl:   0) - TestLvl\n"))
	Print("TestLvl")
	assert.True(t, ContainsStdOut("I : (                             log.TestLvl:   0) - TestLvl\n"))
	Warn("TestLvl")
	assert.True(t, ContainsStdErr("W : (                             log.TestLvl:   0) - TestLvl\n"))
}
