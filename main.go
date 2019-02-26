package main

import (
	"os"
	"runtime"

	"github.com/lucaspiller/watchsumo-checker/cmd"
	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

func init() {
	// Set log level for logrus
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	// Increase GOMAXPROCS if there is only 1 CPU
	var cpus = runtime.NumCPU()
	if cpus < 2 {
		log.Info("Setting GOMAXPROCS to 2")
		runtime.GOMAXPROCS(2)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "Checker"
	app.Commands = []*cli.Command{
		cmd.Check,
		cmd.Start,
	}
	app.Run(os.Args)
}
