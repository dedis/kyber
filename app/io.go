package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/dedis/onet/log"
)

var in *bufio.Reader
var out io.Writer

func init() {
	in = bufio.NewReader(os.Stdin)
	out = os.Stdout
}

// TildeToHome takes a path and replaces an eventual "~" with the home-directory.
// If the user-directory is not defined it will return a path relative to the
// root-directory "/".
func TildeToHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		usr, err := user.Current()
		log.ErrFatal(err, "Got error while fetching home-directory")
		return usr.HomeDir + path[1:]
	}
	return path
}

// Input prints the arguments given with an 'input'-format and
// proposes the 'def' string as default. If the user presses
// 'enter', the 'dev' will be returned.
// In the case of an error it will Fatal.
func Input(def string, args ...interface{}) string {
	fmt.Fprint(out, args...)
	fmt.Fprintf(out, " [%s]: ", def)
	str, err := in.ReadString('\n')
	if err != nil {
		log.Fatal("Could not read input.")
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return def
	}
	return str
}

// Inputf takes a format string and arguments and calls
// Input.
func Inputf(def string, f string, args ...interface{}) string {
	return Input(def, fmt.Sprintf(f, args...))
}

// InputYN asks a Yes/No question. Anything else than upper/lower-case
// 'y' will be interpreted as no.
func InputYN(def bool, args ...interface{}) bool {
	defStr := "Yn"
	if !def {
		defStr = "Ny"
	}
	return strings.ToLower(string(Input(defStr, args...)[0])) == "y"
}

// Copy makes a copy of a local file with the same file-mode-bits set.
func Copy(dst, src string) error {
	info, err := os.Stat(dst)
	if err == nil && info.IsDir() {
		return Copy(path.Join(dst, path.Base(src)), src)
	}
	fSrc, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fSrc.Close()
	stat, err := fSrc.Stat()
	if err != nil {
		return err
	}
	fDst, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, stat.Mode())
	if err != nil {
		return err
	}
	defer fDst.Close()
	_, err = io.Copy(fDst, fSrc)
	return err
}
