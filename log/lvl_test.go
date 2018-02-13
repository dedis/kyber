package log

import (
	"os"
	"strings"
	"testing"

	"errors"

	"github.com/stretchr/testify/assert"
)

func init() {
	outputLines = false
	SetUseColors(false)
	clearEnv()
}

func TestTime(t *testing.T) {
	SetDebugVisible(1)
	GetStdOut()
	Lvl1("No time")
	assert.True(t, containsStdOut("1 : ("))
	SetShowTime(true)
	defer func() { SetShowTime(false) }()
	Lvl1("With time")
	str := GetStdOut()
	if strings.Contains(str, "1 : (") {
		t.Fatal("Didn't get correct string: ", str)
	}
	if strings.Contains(str, " +") {
		t.Fatal("Didn't get correct string: ", str)
	}
	if !strings.Contains(str, "With time") {
		t.Fatal("Didn't get correct string: ", str)
	}
}

func TestFlags(t *testing.T) {
	lvl := DebugVisible()
	time := ShowTime()
	color := UseColors()
	SetDebugVisible(1)

	clearEnv()
	ParseEnv()
	if DebugVisible() != 1 {
		t.Fatal("Debugvisible should be 1")
	}
	if ShowTime() {
		t.Fatal("ShowTime should be false")
	}
	if UseColors() {
		t.Fatal("UseColors should be true")
	}

	os.Setenv("DEBUG_LVL", "3")
	os.Setenv("DEBUG_TIME", "true")
	os.Setenv("DEBUG_COLOR", "false")
	ParseEnv()
	if DebugVisible() != 3 {
		t.Fatal("DebugVisible should be 3")
	}
	if !ShowTime() {
		t.Fatal("ShowTime should be true")
	}
	if UseColors() {
		t.Fatal("UseColors should be false")
	}

	os.Setenv("DEBUG_LVL", "")
	os.Setenv("DEBUG_TIME", "")
	os.Setenv("DEBUG_COLOR", "")
	SetDebugVisible(lvl)
	SetShowTime(time)
	SetUseColors(color)
}

func TestOutputFuncs(t *testing.T) {
	ErrFatal(checkOutput(func() {
		Lvl1("Testing stdout")
	}, true, false))
	ErrFatal(checkOutput(func() {
		LLvl1("Testing stdout")
	}, true, false))
	ErrFatal(checkOutput(func() {
		Print("Testing stdout")
	}, true, false))
	ErrFatal(checkOutput(func() {
		Warn("Testing stdout")
	}, false, true))
	ErrFatal(checkOutput(func() {
		Error("Testing errout")
	}, false, true))
}

func checkOutput(f func(), wantsStd, wantsErr bool) error {
	f()
	stdStr := GetStdOut()
	errStr := GetStdErr()
	if wantsStd {
		if len(stdStr) == 0 {
			return errors.New("Stdout was empty")
		}
	} else {
		if len(stdStr) > 0 {
			return errors.New("Stdout was full")
		}
	}
	if wantsErr {
		if len(errStr) == 0 {
			return errors.New("Stderr was empty")
		}
	} else {
		if len(errStr) > 0 {
			return errors.New("Stderr was full")
		}
	}
	return nil
}

func ExampleLvl2() {
	SetDebugVisible(2)
	OutputToOs()
	Lvl1("Level1")
	Lvl2("Level2")
	Lvl3("Level3")
	Lvl4("Level4")
	Lvl5("Level5")
	OutputToBuf()
	SetDebugVisible(1)

	// Output:
	// 1 : (log.ExampleLvl2: 0) - Level1
	// 2 : (log.ExampleLvl2: 0) - Level2
}

func ExampleLvl1() {
	OutputToOs()
	Lvl1("Multiple", "parameters")
	OutputToBuf()

	// Output:
	// 1 : (log.ExampleLvl1: 0) - Multiple parameters
}

func ExampleLLvl1() {
	OutputToOs()
	Lvl1("Lvl output")
	LLvl1("LLvl output")
	Lvlf1("Lvlf output")
	LLvlf1("LLvlf output")
	OutputToBuf()

	// Output:
	// 1 : (log.ExampleLLvl1: 0) - Lvl output
	// 1!: (log.ExampleLLvl1: 0) - LLvl output
	// 1 : (log.ExampleLLvl1: 0) - Lvlf output
	// 1!: (log.ExampleLLvl1: 0) - LLvlf output
}

func thisIsAVeryLongFunctionNameThatWillOverflow() {
	OutputToOs()
	Lvl1("Overflow")
}

func ExampleLvlf1() {
	OutputToOs()
	Lvl1("Before")
	thisIsAVeryLongFunctionNameThatWillOverflow()
	Lvl1("After")
	OutputToBuf()

	// Output:
	// 1 : (log.ExampleLvlf1: 0) - Before
	// 1 : (log.thisIsAVeryLongFunctionNameThatWillOverflow: 0) - Overflow
	// 1 : (log.ExampleLvlf1: 0) - After
}

func ExampleLvl3() {
	NamePadding = -1
	OutputToOs()
	Lvl1("Before")
	thisIsAVeryLongFunctionNameThatWillOverflow()
	Lvl1("After")
	OutputToBuf()

	// Output:
	// 1 : (log.ExampleLvl3: 0) - Before
	// 1 : (log.thisIsAVeryLongFunctionNameThatWillOverflow: 0) - Overflow
	// 1 : (log.ExampleLvl3: 0) - After
}

func clearEnv() {
	os.Setenv("DEBUG_LVL", "")
	os.Setenv("DEBUG_TIME", "")
	os.Setenv("DEBUG_COLOR", "")
}
