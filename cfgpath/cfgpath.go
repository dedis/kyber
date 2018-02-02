package cfgpath

import (
	"os"
	"os/user"
	"path"
	"runtime"

	"github.com/dedis/onet/log"
)

// GetConfigPath returns the location for which the configuration files are stored.
// Linux:	we follow the XDG Base Directory specification
// macOS:	$HOME/Library/Application Support/appName
// Windows:	%AppData%/appName
// Other:	./appName (we use current directory)
func GetConfigPath(appName string) string {
	if len(appName) == 0 {
		log.Panic("appName cannot be empty")
	}

	u, err := user.Current()
	if err != nil {
		log.Error("could not get your home-directory switching back to current dir.")
		return getCurrentDir(appName)
	}

	switch runtime.GOOS {
	case "darwin":
		return path.Join(u.HomeDir, "Library", "Application Support", appName)
	case "windows":
		return path.Join(os.Getenv("APPDATA"), appName)
	case "linux", "freebsd":
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg != "" {
			return path.Join(xdg, appName)
		}
		return path.Join(u.HomeDir, ".config", appName)
	default:
		return getCurrentDir(appName)
	}
}

// GetDataPath returns the location for which the data files are stored.
// Linux:	we follow the XDG Base Directory specification
// All others:	the "data" directory in the path retunred by GetConfigPath
func GetDataPath(appName string) string {
	switch runtime.GOOS {
	case "linux", "freebsd":
		u, err := user.Current()
		if err != nil {
			log.Error("could not get your home-directory switching back to current dir.")
			return path.Join(getCurrentDir(appName), "data")
		}
		xdg := os.Getenv("XDG_DATA_HOME")
		if xdg != "" {
			return path.Join(xdg, appName)
		}
		return path.Join(u.HomeDir, ".local", "share", appName)
	default:
		p := GetConfigPath(appName)
		return path.Join(p, "data")
	}
}

func getCurrentDir(appName string) string {
	curr, err := os.Getwd()
	if err != nil {
		log.Panic("impossible to get the current directory:", err)
	}
	return path.Join(curr, appName)
}
