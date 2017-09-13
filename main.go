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
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	chain     = flag.String("chain", "prometheus", "Netfilter chain to monitor")
	namespace = flag.String("namespace", "nfprom", "Namespace (prefix) to use for Prometheus metrics")
	ipv4      = flag.Bool("ipv4", true, "Enable/disable collection of IPv4 stats")
	ipv6      = flag.Bool("ipv6", false, "Enable/disable collection of IPv6 stats")
	listen    = flag.String("addr", ":9914", "name:port, ipv4:port or [ipv6]:port to listen on")
)

func main() {
	flag.Parse()
	log.Printf("Prometheus iptables exporter starting")
	prometheus.MustRegister(newIptablesCollector(*chain, *namespace, *ipv4, *ipv6))
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(*listen, nil)
}

type iptablesCollector struct {
	do_ipv4      bool
	do_ipv6      bool
	chain        string
	namespace    string
	packetsTotal *prometheus.Desc
	bytesTotal   *prometheus.Desc
}

func newIptablesCollector(chain, namespace string, do_ipv4, do_ipv6 bool) prometheus.Collector {
	c := iptablesCollector{
		do_ipv4:   do_ipv4,
		do_ipv6:   do_ipv6,
		chain:     chain,
		namespace: namespace,
		packetsTotal: prometheus.NewDesc(
			namespace+"_packets_total",
			"Total number of packets on this port/proto/direction",
			[]string{"l2proto", "l3proto", "address", "port", "direction"},
			nil,
		),
		bytesTotal: prometheus.NewDesc(
			namespace+"_bytes_total",
			"Total number of bytes on this port/proto/direction",
			[]string{"l2proto", "l3proto", "address", "port", "direction"},
			nil,
		),
	}
	return &c
}

func (c *iptablesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.bytesTotal
}

// Collect returns the current state of all metrics of the collector.
func (c *iptablesCollector) Collect(ch chan<- prometheus.Metric) {
	if c.do_ipv4 {
		c.iptablesCollect(ch, "ipv4")
	}
	if c.do_ipv6 {
		c.iptablesCollect(ch, "ipv6")
	}
}

func (c *iptablesCollector) iptablesCollect(ch chan<- prometheus.Metric, l2proto string) {
	data := getIptablesData(l2proto)
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineno := 0
	for scanner.Scan() {
		lineno += 1
		tokens := strings.Split(scanner.Text(), " ")
		if len(tokens) < 4 || tokens[2] != "prometheus" || tokens[4] == "RETURN" {
			continue
		}
		// We can now be sure the tokens are:
		// [272282:51019430] -A prometheus -s 88.99.5.140/32 -p tcp -m tcp --sport 22 -j RETURN]
		// [231097:107682563] -A prometheus -d 88.99.5.140/32 -p tcp -m tcp --dport 22 -j RETURN]
		bytes, packets, err := extractCounters(tokens[0])
		if err != nil {
			fmt.Printf("Malformed packet/byte count on line %d: %v", lineno, err)
			continue
		}
		l3proto := extractProto(tokens)
		direction, address, port := extractDirectionAddrPort(tokens)
		ch <- prometheus.MustNewConstMetric(
			c.packetsTotal,
			prometheus.CounterValue,
			float64(packets),
			l2proto, l3proto, address, port, direction)
		ch <- prometheus.MustNewConstMetric(
			c.bytesTotal,
			prometheus.CounterValue,
			float64(bytes),
			l2proto, l3proto, address, port, direction)
	}

}

func getIptablesData(l2proto string) string {
	var cmdline []string
	if l2proto == "ipv4" {
		cmdline = []string{"sudo", "iptables-save", "-c", "-t", "filter"}
	} else {
		cmdline = []string{"sudo", "ip6tables-save", "-c", "-t", "filter"}
	}
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(fmt.Printf("cmd.StdoutPipe(): %v", err))
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(fmt.Printf("cmd.Start(): %v", err))
	}
	b, err := ioutil.ReadAll(stdout)
	if err != nil {
		log.Fatal(fmt.Printf("ioutil.ReadAll(): %v", err))
	}
	return string(b)
}

func extractCounters(data string) (uint64, uint64, error) {
	tokens := strings.Split(data[1:len(data)-1], ":")
	if len(tokens) != 2 {
		return 0, 0, fmt.Errorf("Could not parse %v as [packets:bytes]: %v", data, tokens)
	}
	packets, err := strconv.ParseUint(tokens[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("Could not parse %v as uint64", tokens[0])
	}
	bytes, err := strconv.ParseUint(tokens[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("Could not parse %v as uint64", tokens[1])
	}
	return packets, bytes, nil
}

func extractProto(data []string) string {
	for idx, token := range data {
		if token == "-p" {
			return data[idx+1]
		}
	}
	return "unknown"
}

func extractDirectionAddrPort(data []string) (string, string, string) {
	var needle, address, direction string
	// First, figure out if this is incoming or outgoing
	for idx, token := range data {
		if token == "-s" {
			direction = "out"
			address = data[idx+1]
			needle = "--sport"
			break
		}
		if token == "-d" {
			direction = "in"
			address = data[idx+1]
			needle = "--dport"
			break
		}
	}
	for idx, token := range data {
		if token == needle {
			return direction, address, data[idx+1]
		}
	}
	return "", "", ""
}
