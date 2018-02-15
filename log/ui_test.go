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
	assert.True(t, containsStdOut("[+] Python\n"))
	SetDebugVisible(FormatNone)
	Info("None")
	assert.True(t, containsStdOut("None\n"))
	Info("None", "Python")
	assert.True(t, containsStdOut("None Python\n"))
	SetDebugVisible(1)
}

func TestLvl(t *testing.T) {
	SetDebugVisible(1)
	Info("TestLvl")
	assert.True(t, containsStdOut("I : (log.TestLvl: 0) - TestLvl\n"))
	Print("TestLvl")
	assert.True(t, containsStdOut("I : (log.TestLvl: 0) - TestLvl\n"))
	Warn("TestLvl")
	assert.True(t, containsStdErr("W : (log.TestLvl: 0) - TestLvl\n"))
}
