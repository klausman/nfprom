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
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	addrFamily = flag.String("nfta", "inet", "Address family to use for nftables")
	nftable    = flag.String("nftt", "firewall", "Nftables table to use")
	nftchain   = flag.String("nftc", "accounting", "Nftables chain to use")
)

type nftablesCollector struct {
	namespace    string
	packetsTotal *prometheus.Desc
	bytesTotal   *prometheus.Desc
}

func newNftablesCollector(namespace string) prometheus.Collector {
	c := nftablesCollector{
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

func (c *nftablesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.bytesTotal
}

// Collect returns the current state of all metrics of the collector.
func (c *nftablesCollector) Collect(ch chan<- prometheus.Metric) {
	c.nftablesCollect(ch)
}

func (c *nftablesCollector) nftablesCollect(ch chan<- prometheus.Metric) {
	data := getNftablesData()
	if data == "" {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineno := 0
	for scanner.Scan() {
		lineno += 1
		line := strings.Trim(scanner.Text(), "\r\n\t ")
		//log.Printf("Line: %#v", line)
		if strings.Contains(line, "}") || strings.Contains(line, "{") || line == "return" {
			continue
		}
		tokens := strings.Split(line, " ")
		packets, bytes, err := extractNftCounters(tokens)
		if err != nil {
			fmt.Printf("Malformed packet/byte count on line %d: %v", lineno, err)
			continue
		}
		l3proto := extractNftL3Proto(tokens)
		direction, address, port := extractNftDirectionAddrPort(tokens)
		l2proto := "ipv4"
		if strings.Contains(address, ":") {
			l2proto = "ipv6"
		}
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

func getNftablesData() string {
	cmdline := []string{"sudo", "nft", "list", "chain", *addrFamily, *nftable, *nftchain}
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(fmt.Printf("cmd.StdoutPipe(): %v", err))
		return ""
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		log.Fatal(fmt.Printf("cmd.Start(): %v", err))
		return ""
	}
	defer cmd.Wait()
	b, err := ioutil.ReadAll(stdout)
	if err != nil {
		log.Fatal(fmt.Printf("ioutil.ReadAll(): %v", err))
		return ""
	}
	return string(b)
}

func extractNftCounters(data []string) (uint64, uint64, error) {
	pci := stringIndexSL("packets", data) + 1
	if pci == 0 || pci > len(data) { // -1 is not found, but we add one above
		return 0, 0, fmt.Errorf("could not parse packet counter (i: %d l: %d) on line %v", pci, len(data), data)
	}
	bci := stringIndexSL("bytes", data) + 1
	if bci == 0 || bci > len(data) { // -1 is not found, but we add one above
		return 0, 0, fmt.Errorf("could not parse byte counter on line %v", data)
	}
	pc, err := strconv.ParseUint(data[pci], 10, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("could not parse packet counter %v", data[pci])
	}
	bc, err := strconv.ParseUint(data[pci], 10, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("could not parse byte counter %v", data[bci])
	}
	return pc, bc, nil
}

func extractNftL3Proto(data []string) string {
	for _, token := range data {
		if token == "tcp" || token == "udp" || token == "icmp" {
			return token
		}
	}
	return "unknown"
}

func extractNftDirectionAddrPort(data []string) (string, string, string) {
	var needle, address, direction string
	// First, figure out if this is incoming or outgoing
	for idx, token := range data {
		if token == "saddr" {
			direction = "out"
			address = data[idx+1]
			needle = "sport"
			break
		}
		if token == "daddr" {
			direction = "in"
			address = data[idx+1]
			needle = "dport"
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

func stringIndexSL(s string, sl []string) int {
	//log.Printf("Finding %#v in %#v", s, sl)
	for i, c := range sl {
		//log.Printf("%#v == %#v?", s, c)
		if s == c {
			//log.Printf("Match!")
			return i
		}
	}
	return -1
}
