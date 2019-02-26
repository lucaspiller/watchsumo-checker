package cmd

import (
	"net/url"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lucaspiller/watchsumo-checker/checker"
	"github.com/lucaspiller/watchsumo-checker/types"
	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

var (
	// Check command
	Check = &cli.Command{
		Name:   "check",
		Action: runCheck,
	}
)

func runCheck(c *cli.Context) error {
	// Enable debugging
	log.SetLevel(log.DebugLevel)

	// Parse URL
	url, err := url.Parse(c.Args().First())
	if err != nil || url.Host == "" {
		return cli.Exit("Invalid URL", 1)
	}

	checkRequest := &types.CheckRequest{
		Ref:    "-1",
		Method: "GET",
		URL:    url,
		//Headers:      make(map[string][]string),
		//Body:         "",
		Timeout: 15 * time.Second,
		Options: types.CheckOptions{
			GetFallback:     true,
			IgnoreTLSErrors: false,
			FollowRedirects: true,
		},
	}

	checker := checker.Init(checkRequest)
	checker.Perform()

	if checker.Success {
		log.Info("Website is UP")
	} else {
		log.WithFields(log.Fields{
			"error": checker.Res.Error,
		}).Info("Website is DOWN")
	}

	// Remove body from output
	checker.Res.Body = ""

	spew.Dump(checker.Res)

	return nil
}
