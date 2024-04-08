// Copyright (C) 2017 Tobias Klausmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

const (
	nfpversion = "0.2.0"
)

var (
	listen    = flag.String("listen", ":9830", "ip:port to listen on")
	namespace = flag.String("namespace", "nfprom", "Namespace (prefix) to use for Prometheus metrics")
	nftdata   = flag.String("jsonfile", "nftdata.json", "Path to file for JSON data")
	timeout   = flag.Duration("timeout", time.Second*3, "Timeout for webserver reading client request")

	group    = flag.String("g", "nogroup", "group to switch to for privilege separation (GID or name)")
	username = flag.String("u", "nobody", "user to switch to for privilege separation (UID or name)")

	version = flag.Bool("v", false, "Print version and exit (disregard other flags")

	webmode = flag.Bool("w", false, "internal flag (do not use)")
)

func main() {
	flag.Parse()
	if *version {
		fmt.Printf("nfprom version %s\n", nfpversion)
		os.Exit(0)
	}
	pid := os.Getpid()
	if *webmode {
		log.Printf("[%d] Prometheus nftables exporter v%s (webserver process) starting", pid, nfpversion)
	} else {
		log.Printf("[%d] Prometheus nftables exporter v%s (nftables/netlink process) starting", pid, nfpversion)
	}

	if *webmode {
		log.Printf("[%d] Dropping privileges", pid)
		err := dropPrivileges(*username, *group)
		if err != nil {
			log.Printf("[%d] Could not drop privileges: %s", pid, err)
			// TODO: kill other process
			os.Exit(-1)
		}
		log.Printf("[%d] Starting webserver on %s", pid, *listen)
		http.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{
			Addr:              *listen,
			ReadHeaderTimeout: *timeout,
		}

		reg := prometheus.NewPedanticRegistry()
		jt, err := newJSONCollector(*namespace)
		if err != nil {
			log.Printf("[%d] Could not create JSON collector: %s", pid, err)
			os.Exit(-1)
		}
		prometheus.MustRegister(jt, reg)
		panic(srv.ListenAndServe())
	}
	log.Printf("[%d] Forking off webserver process", pid)
	wscmd := forkWebserver()
	defer killNoCheck(wscmd)
	log.Printf("[%d] Starting NFT exporter", pid)
	go func(wscmd *exec.Cmd) {
		pid := os.Getpid()
		err := wscmd.Wait()
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			log.Printf("[%d] Webserver process with pid %d exited with code %d", pid, eerr.Pid(), eerr.ExitCode())
			log.Printf("[%d] Webserver stderr: %v", pid, string(eerr.Stderr))
		} else {
			log.Printf("[%d] Webserver process failed to launch: %s", pid, err)
		}
		log.Printf("[%d] Nftables/Netlink process exiting", pid)
		// an os.Exit implicitly does NOT run the defer kill... above,
		// so we avoid a loop-de-loop here
		os.Exit(-1)
	}(wscmd)
	exportNftForever()
	// if we ever get here, we need to get rid of the child as well
}

func dropPrivileges(username, group string) error {
	var uid, gid int
	var err error
	if uid, err = strconv.Atoi(username); err != nil {
		u, err := user.Lookup(username)
		if err != nil {
			return fmt.Errorf("could not look up UID for user %s: %w", username, err)
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("could not convert string uid %v to intuid: %w", u.Uid, err)
		}

	}
	if gid, err = strconv.Atoi(group); err != nil {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("could not look up GID for group %s: %w", username, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("could not convert string gid %v to intgid: %w", g.Gid, err)
		}

	}
	err = unix.Setgid(gid)
	if err != nil {
		return fmt.Errorf("could not drop privs to group %s/%d: %w", group, gid, err)
	}
	err = unix.Setuid(uid)
	if err != nil {
		return fmt.Errorf("could not drop privs to user %s/%d: %w", username, uid, err)
	}
	return nil
}

func killNoCheck(cmd *exec.Cmd) {
	//nolint:errcheck // There is no point in checking the error here: we're
	// into our own shutdown by now
	cmd.Process.Kill()
}
