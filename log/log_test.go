package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	// Flush buffers from previous tests.
	GetStdOut()
	GetStdErr()
	old := DebugVisible()
	SetDebugVisible(1)

	assert.False(t, ContainsStdOut("info"))
	assert.False(t, ContainsStdErr("error"))
	Info("Some information")
	assert.True(t, ContainsStdOut("info"))
	Error("Some error")
	assert.True(t, ContainsStdErr("error"))

	SetDebugVisible(old)
}
