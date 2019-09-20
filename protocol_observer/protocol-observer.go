// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

// +build go1.13

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	cgm "github.com/circonus-labs/circonus-gometrics/v3"
	"github.com/circonus-labs/wirelatency"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
)

var version = "0.0.3"

type localip struct{}

func (r *localip) String() string {
	return "complex multiple values"
}

func (r *localip) Set(value string) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return errors.Errorf("Invalid IP address: %s\n", value)
	}
	wirelatency.AddLocalIP(ip)
	return nil
}

type regflag struct{}

func (r *regflag) String() string {
	return "complex multiple values"
}

type wiring struct {
	proto  string
	port   layers.TCPPort
	config *string
}

var wirings = make([]wiring, 0, 1)

func (r *regflag) Set(value string) error {
	parts := strings.SplitN(value, ":", 3)
	proto := parts[0]
	port := layers.TCPPort(0)
	var config *string
	if len(parts) > 1 {
		nport, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("Bad port: %v", err)
		}
		port = layers.TCPPort(nport)
	}
	if len(parts) > 2 {
		config = &parts[2]
	}
	wirings = append(wirings, wiring{
		proto:  proto,
		port:   port,
		config: config,
	})
	return nil
}

var debugCirconus = flag.Bool("debugCirconus", false, "Debug CirconusMetrics")
var vflag = flag.Bool("v", false, "Show version information")
var quiet = flag.Bool("s", false, "Be quiet")
var apiurl = flag.String("apiurl", "", "Circonus API URL")
var apitoken = flag.String("apitoken", "", "Circonus API Token")
var instanceid = flag.String("instanceid", "", "This machine's unique identifier")
var submissionurl = flag.String("submissionurl", "", "Optional HTTPTrap URL")
var checkid = flag.String("checkid", "", "The Circonus check ID (not bundle id)")
var brokergroupid = flag.String("brokergroupid", "", "The broker group id")
var pprofNet = flag.Int("pprof_net", 0, "Port on which to listen for pprof")
var brokertag = flag.String("brokertag", "", "The broker tag for selection")
var autoRestart = flag.String("auto_restart", "", "Restart duration")

func main() {
	var origArgs = make([]string, len(os.Args))
	copy(origArgs, os.Args)
	origEnv := os.Environ()

	var localIPFlag localip
	flag.Var(&localIPFlag, "localip", "<ipaddress>")
	var registrationsFlag regflag
	flag.Var(&registrationsFlag, "wire", "<name>:<port>[:<config>]")
	flag.Parse()

	if *vflag {
		fmt.Printf("%s version %s\n", os.Args[0], version)
		os.Exit(0)
	}

	if *autoRestart != "" {
		dur, err := time.ParseDuration(*autoRestart)
		if err != nil {
			log.Fatalf("Bad auto_restart duration: %v\n", err)
		}
		go func(d time.Duration) {
			time.Sleep(d)
			wirelatency.Close()
			if err := syscall.Exec(origArgs[0], origArgs, origEnv); err != nil {
				log.Fatalf("Failed to start process replacement (%v)\n", err)
			}
			log.Fatalf("Failed process replacement\n")
		}(dur)
	}

	if *pprofNet > 0 {
		go func() {
			log.Println(http.ListenAndServe("localhost:"+strconv.Itoa(*pprofNet), nil))
		}()
	}
	if *apitoken == "" && *submissionurl == "" {
		log.Printf("No Circonus API Token specified, no reporting will happen.")
	} else {
		cfg := &cgm.Config{}
		cfg.CheckManager.Check.InstanceID = *instanceid
		cfg.CheckManager.Check.SubmissionURL = *submissionurl
		cfg.CheckManager.Check.ID = *checkid
		cfg.CheckManager.Broker.ID = *brokergroupid
		cfg.CheckManager.Broker.SelectTag = *brokertag
		cfg.CheckManager.API.URL = *apiurl
		cfg.CheckManager.API.TokenKey = *apitoken
		cfg.Debug = *debugCirconus
		metrics, err := cgm.NewCirconusMetrics(cfg)
		if err != nil {
			log.Printf("Error initializing Circonus metrics, no reporting will happen. (%v)", err)
		} else {
			metrics.Start()
			wirelatency.SetMetrics(metrics)
		}
	}

	for _, w := range wirings {
		if err := wirelatency.RegisterTCPPort(w.port, w.proto, w.config); err != nil {
			log.Fatalf("Failed to register %v on port %v: %v", w.proto, w.port, err)
		}
	}
	prots := wirelatency.Protocols()
	mapping := wirelatency.PortMap()
	if len(mapping) == 0 {
		fmt.Printf("Usage:\n\t-wire <protocol>[:<port>[:<config>]]\n\n")
		fmt.Printf("No -wire <mapping> specified, available:\n")
		for protocol := range prots {
			fmt.Printf("\t-wire %v\n", protocol)
		}
		fmt.Printf("\nplease specify at least one wire mapping.\n")
		fmt.Printf("\nUse -help for many more options.\n")
		os.Exit(2)
	}
	for port, twa := range mapping {
		config := twa.Config
		if !*quiet {
			if config == nil {
				log.Printf("\t*:%v -> %v", port, (*twa.Proto()).Name())
			} else {
				log.Printf("\t*:%v -> %v(%v)", port, (*twa.Proto()).Name(), *config)
			}
		}
	}
	wirelatency.Capture()
}
