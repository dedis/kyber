// Dedis script modified from github.com/dyv/dedis-ci-script.go
// to take into account deleted files
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// get all changed files + new files - removed files
	cmdStr := "git diff --name-status origin/master | grep -v ^D | cut -f2"
	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("error running git diff: ", err)
		os.Exit(1)
	}
	fmt.Println("git diff --name-only production/master: ", string(output))
	fnames := strings.Split(string(output), "\n")
	fmt.Println("Files changed from origin/master: ", fnames)
	good := true
	for _, fn := range fnames {
		// go source code must be properly formatted
		if strings.HasSuffix(fn, ".go") {
			if _, err := os.Stat(fn); os.IsNotExist(err) {
				fmt.Printf("no such go file: %s\n", fn)
				continue
			}
			fmtCmd := exec.Command("gofmt", "-l", fn)
			fmtCmd.Stderr = os.Stderr
			out, err := fmtCmd.Output()
			if err != nil {
				fmt.Println("Error Running go fmt: ", err)
				os.Exit(1)
			}
			// if go fmt returns anything that means the file has been
			// formatted and did not conform.
			if len(out) != 0 {
				fmt.Println("File not properly formatted: ", fn)
				good = false
			}
		}
	}
	if good == false {
		fmt.Println("Failed: files not properly formatted: Use gofmt")
		os.Exit(1)
	}
	tests := exec.Command("go", "test", "-v", "./...")
	tests.Stderr = os.Stderr
	tests.Stdout = os.Stdout
	err = tests.Run()
	if err != nil {
		fmt.Println("Tests Failed")
		os.Exit(1)
	}
}
