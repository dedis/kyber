package app

import (
	"os"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"gopkg.in/urfave/cli.v1"
)

// DefaultConfig is the name of the binary we produce and is used to create a directory
// folder with this name
const DefaultConfig = "cothority"

// CmdSetup is used to setup the cothority
var CmdSetup = cli.Command{
	Name:    "setup",
	Aliases: []string{"s"},
	Usage:   "Setup the configuration for the server (interactive)",
	Action: func(c *cli.Context) error {
		InteractiveConfig("cothority")
		return nil
	},
}

// CmdServer is used to start the server
var CmdServer = cli.Command{
	Name:  "server",
	Usage: "Run the cothority server",
	/*Action: func(c *cli.Context) {*/
	//runServer(c)
	/*},*/
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Value: GetDefaultConfigFile(DefaultConfig),
			Usage: "Configuration file of the server",
		},
	},
}

// FlagDebug offers a debug-flag
var FlagDebug = cli.IntFlag{
	Name:  "debug, d",
	Value: 0,
	Usage: "debug-level: 1 for terse, 5 for maximal",
}

// FlagConfig indicates where the configuration-file is stored
var FlagConfig = cli.StringFlag{
	Name:  "config, c",
	Value: GetDefaultConfigFile(DefaultConfig),
	Usage: "Configuration file of the server",
}

// Server runs a stand-alone server with all imported services
func Server(suite network.Suite) {
	cliApp := cli.NewApp()
	cliApp.Name = "Cothority server"
	cliApp.Usage = "Serve a cothority"

	cliApp.Commands = []cli.Command{
		CmdSetup,
	}
	cliApp.Flags = []cli.Flag{
		FlagDebug,
		FlagConfig,
		//cli.StringFlag{Name: "test.run"},
		//cli.StringFlag{Name: "test.v"},
	}
	CmdServer.Action = func(c *cli.Context) {
		runServer(c, suite)
	}
	cliApp.Commands = append(cliApp.Commands, CmdServer)

	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("d"))
		return nil
	}

	// default action
	cliApp.Action = func(c *cli.Context) error {
		runServer(c, suite)
		return nil
	}

	err := cliApp.Run(os.Args)
	log.ErrFatal(err)
}

// RunServer starts the server
func runServer(ctx *cli.Context, suite network.Suite) {
	// first check the options
	config := ctx.String("config")
	RunServer(config, suite)
}
