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

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	nfpversion = "0.1.0"
)

var (
	mode      = flag.String("mode", "ipt", "Mode to run in, one of 'ipt' or 'nft'")
	namespace = flag.String("namespace", "nfprom", "Namespace (prefix) to use for Prometheus metrics")
	listen    = flag.String("addr", ":9830", "name:port, ipv4:port or [ipv6]:port to listen on")
	version   = flag.Bool("v", false, "Print version and exit (disregard other flags")
)

func main() {
	flag.Parse()
	if *version {
		fmt.Printf("nfprom version %s\n", nfpversion)
		os.Exit(0)
	}
	log.Printf("Prometheus iptables exporter starting")
	switch *mode {
	case "ipt":
		prometheus.MustRegister(newIptablesCollector(*chain, *namespace, *ipv4, *ipv6))
	case "nft":
		prometheus.MustRegister(newNftablesCollector(*namespace))
	default:
		log.Fatalf("Mode '%s' not recognized. Must be 'nft' or 'ipt'", *mode)
	}
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(*listen, nil)
}
