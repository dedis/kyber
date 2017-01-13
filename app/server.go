package app

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/dedis/onet"
	"github.com/dedis/onet/crypto"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"

	// CoSi-protocol is not part of the cothority.

	// For the moment, the server only serves CoSi requests
	"github.com/dedis/crypto/abstract"
	crypconf "github.com/dedis/crypto/config"
)

// DefaultServerConfig is the default server configuration file-name.
const DefaultServerConfig = "private.toml"

// DefaultGroupFile is the default group definition file-name.
const DefaultGroupFile = "public.toml"

// DefaultPort to listen and connect to. As of this writing, this port is not listed in
// /etc/services
const DefaultPort = 6879

// DefaultAddress where to be contacted by other servers.
const DefaultAddress = "127.0.0.1"

// Service used to get the public IP-address.
const whatsMyIP = "http://www.whatsmyip.org/"

// InteractiveConfig uses stdin to get the [address:]PORT of the server.
// If no address is given, whatsMyIP is used to find the public IP. In case
// no public IP can be configured, localhost will be used.
// If everything is OK, the configuration-files will be written.
// In case of an error this method Fatals.
func InteractiveConfig(binaryName string) {
	log.Info("Setting up a cothority-server.")
	str := Inputf(strconv.Itoa(DefaultPort), "Please enter the [address:]PORT for incoming requests")
	// let's dissect the port / IP
	var hostStr string
	var ipProvided = true
	var portStr string
	var serverBinding network.Address
	if !strings.Contains(str, ":") {
		str = ":" + str
	}
	host, port, err := net.SplitHostPort(str)
	log.ErrFatal(err, "Couldn't interpret", str)

	if str == "" {
		portStr = strconv.Itoa(DefaultPort)
		hostStr = "0.0.0.0"
		ipProvided = false
	} else if host == "" {
		// one element provided
		// ip
		ipProvided = false
		hostStr = "0.0.0.0"
		portStr = port
	} else {
		hostStr = host
		portStr = port
	}

	serverBinding = network.NewTCPAddress(hostStr + ":" + portStr)
	if !serverBinding.Valid() {
		log.Error("Unable to validate address given", serverBinding)
		return
	}

	log.Info("We now need to get a reachable address for other Servers")
	log.Info("and clients to contact you. This address will be put in a group definition")
	log.Info("file that you can share and combine with others to form a Cothority roster.")

	var publicAddress network.Address
	var failedPublic bool
	// if IP was not provided then let's get the public IP address
	if !ipProvided {
		resp, err := http.Get("http://myexternalip.com/raw")
		// cant get the public ip then ask the user for a reachable one
		if err != nil {
			log.Error("Could not get your public IP address")
			failedPublic = true
		} else {
			buff, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Error("Could not parse your public IP address", err)
				failedPublic = true
			} else {
				publicAddress = network.NewTCPAddress(strings.TrimSpace(string(buff)) + ":" + portStr)
			}
		}
	} else {
		publicAddress = serverBinding
	}

	// Let's directly ask the user for a reachable address
	if failedPublic {
		publicAddress = askReachableAddress(portStr)
	} else {
		if publicAddress.Public() {
			// try  to connect to ipfound:portgiven
			tryIP := publicAddress
			log.Info("Check if the address", tryIP, "is reachable from Internet...")
			if err := tryConnect(tryIP, serverBinding); err != nil {
				log.Error("Could not connect to your public IP")
				publicAddress = askReachableAddress(portStr)
			} else {
				publicAddress = tryIP
				log.Info("Address", publicAddress, "is publicly available from Internet.")
			}
		}
	}

	if !publicAddress.Valid() {
		log.Fatal("Could not validate public ip address:", publicAddress)
	}

	// create the keys
	privStr, pubStr := createKeyPair()
	conf := &CothorityConfig{
		Public:  pubStr,
		Private: privStr,
		Address: publicAddress,
		Description: Input("New cothority",
			"Give a description of the cothority"),
	}

	var configDone bool
	var configFolder string
	var defaultFolder = path.Dir(GetDefaultConfigFile(binaryName))
	var configFile string
	var groupFile string

	for !configDone {
		// get name of config file and write to config file
		configFolder = Input(defaultFolder, "Please enter a folder for the configuration files")
		configFile = path.Join(configFolder, DefaultServerConfig)
		groupFile = path.Join(configFolder, DefaultGroupFile)

		// check if the directory exists
		if _, err := os.Stat(configFolder); os.IsNotExist(err) {
			log.Info("Creating inexistant directory configuration", configFolder)
			if err = os.MkdirAll(configFolder, 0744); err != nil {
				log.Fatalf("Could not create directory configuration %s %v", configFolder, err)
			}
		}

		if checkOverwrite(configFile) && checkOverwrite(groupFile) {
			break
		}
	}

	public, err := crypto.StringHexToPub(network.Suite, pubStr)
	if err != nil {
		log.Fatal("Impossible to parse public key:", err)
	}

	server := NewServerToml(network.Suite, public, publicAddress, conf.Description)
	group := NewGroupToml(server)

	saveFiles(conf, configFile, group, groupFile)
	log.Info("All configurations saved, ready to serve signatures now.")
}

// entityListToPublics returns a slice of Points of all elements
// of the roster.
func entityListToPublics(el *onet.Roster) []abstract.Point {
	publics := make([]abstract.Point, len(el.List))
	for i, e := range el.List {
		publics[i] = e.Public
	}
	return publics
}

// Returns true if file exists and user confirms overwriting, or if file doesn't exist.
// Returns false if file exists and user doesn't confirm overwriting.
func checkOverwrite(file string) bool {
	// check if the file exists and ask for override
	if _, err := os.Stat(file); err == nil {
		return InputYN(true, "Configuration file "+file+" already exists. Override?")
	}
	return true
}

// createKeyPair returns the private and public key in hexadecimal representation.
func createKeyPair() (string, string) {
	log.Info("Creating ed25519 private and public keys.")
	kp := crypconf.NewKeyPair(network.Suite)
	privStr, err := crypto.ScalarToStringHex(network.Suite, kp.Secret)
	if err != nil {
		log.Fatal("Error formating private key to hexadecimal. Abort.")
	}
	var point abstract.Point
	// use the transformation for EdDSA signatures
	//point = cosi.Ed25519Public(network.Suite, kp.Secret)
	point = kp.Public
	pubStr, err := crypto.PubToStringHex(network.Suite, point)
	if err != nil {
		log.Fatal("Could not parse public key. Abort.")
	}

	log.Info("Public key: ", pubStr, "\n")
	return privStr, pubStr
}

// saveFiles takes a CothorityConfig and its filename, and a GroupToml and its filename,
// and saves the data to these files.
// In case of a failure it Fatals.
func saveFiles(conf *CothorityConfig, fileConf string, group *GroupToml, fileGroup string) {
	if err := conf.Save(fileConf); err != nil {
		log.Fatal("Unable to write the config to file:", err)
	}
	log.Info("Success! You can now use the CoSi server with the config file", fileConf)
	// group definition part
	if err := group.Save(fileGroup); err != nil {
		log.Fatal("Could not write your group file snippet:", err)
	}

	log.Info("Saved a group definition snippet for your server at", fileGroup,
		group.String())

}

// GetDefaultConfigFile returns the default path to the configuration-path, which
// is ~/.config/binaryName for Unix and ~/Library/binaryName for MacOSX.
// In case of an error it Fatals.
func GetDefaultConfigFile(binaryName string) string {
	u, err := user.Current()
	// can't get the user dir, so fallback to current working dir
	if err != nil {
		log.Error("Could not get your home-directory (", err.Error(), "). Switching back to current dir.")
		if curr, err := os.Getwd(); err != nil {
			log.Fatal("Impossible to get the current directory:", err)
		} else {
			return path.Join(curr, DefaultServerConfig)
		}
	}
	// Fetch standard folders.
	switch runtime.GOOS {
	case "darwin":
		return path.Join(u.HomeDir, "Library", binaryName, DefaultServerConfig)
	default:
		return path.Join(u.HomeDir, ".config", binaryName, DefaultServerConfig)
		// TODO Windows? FreeBSD?
	}
}

// askReachableAddress uses stdin to get the contactable IP-address of the server
// and adding port if necessary.
// In case of an error, it will Fatal.
func askReachableAddress(port string) network.Address {
	ipStr := Input(DefaultAddress, "IP-address where your server can be reached")

	splitted := strings.Split(ipStr, ":")
	if len(splitted) == 2 && splitted[1] != port {
		// if the client gave a port number, it must be the same
		log.Fatal("The port you gave is not the same as the one your server will be listening. Abort.")
	} else if len(splitted) == 2 && net.ParseIP(splitted[0]) == nil {
		// of if the IP address is wrong
		log.Fatal("Invalid IP:port address given:", ipStr)
	} else if len(splitted) == 1 {
		// check if the ip is valid
		if net.ParseIP(ipStr) == nil {
			log.Fatal("Invalid IP address given:", ipStr)
		}
		// add the port
		ipStr = ipStr + ":" + port
	}
	return network.NewTCPAddress(ipStr)
}

// tryConnect binds to the given IP address and ask an internet service to
// connect to it. binding is the address where we must listen (needed because
// the reachable address might not be the same as the binding address => NAT, ip
// rules etc).
// In case anything goes wrong, an error is returned.
func tryConnect(ip, binding network.Address) error {

	stopCh := make(chan bool, 1)
	// let's bind
	go func() {
		ln, err := net.Listen("tcp", binding.NetworkAddress())
		if err != nil {
			log.Error("Trouble with binding to the address:", err)
			return
		}
		con, _ := ln.Accept()
		<-stopCh
		con.Close()
	}()
	defer func() { stopCh <- true }()

	_, port, err := net.SplitHostPort(ip.NetworkAddress())
	if err != nil {
		return err
	}
	values := url.Values{}
	values.Set("port", port)
	values.Set("timeout", "default")

	// ask the check
	url := whatsMyIP + "port-scanner/scan.php"
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Host", "www.whatsmyip.org")
	req.Header.Set("Referer", "http://www.whatsmyip.org/port-scanner/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if !bytes.Contains(buffer, []byte("1")) {
		return errors.New("Address unreachable")
	}
	return nil
}

// RunServer starts a cothority server with the given config file name. It can
// be used by different apps (like CoSi, for example)
func RunServer(configFilename string) {
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		log.Fatalf("[-] Configuration file does not exists. %s", configFilename)
	}
	// Let's read the config
	_, server, err := ParseCothority(configFilename)
	if err != nil {
		log.Fatal("Couldn't parse config:", err)
	}
	server.Start()
}
