//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

func newJSONCollector(namespace string) (prometheus.Collector, error) {
	var c jsonCollector
	_, labels, err := getNftDataFromJSON(*nftdata)
	if err != nil {
		return &c, fmt.Errorf("could not parse metric metadata from JSON: %w", err)
	}
	c = jsonCollector{
		namespace: namespace,
		packetsTotal: prometheus.NewDesc(
			namespace+"_packets_total",
			"Total number of packets on this port/proto/direction",
			labels,
			nil,
		),
		bytesTotal: prometheus.NewDesc(
			namespace+"_bytes_total",
			"Total number of bytes on this port/proto/direction",
			labels,
			nil,
		),
	}
	return &c, nil
}

type jsonCollector struct {
	namespace    string
	packetsTotal *prometheus.Desc
	bytesTotal   *prometheus.Desc
}

func (c *jsonCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect returns the current state of all metrics of the collector.
func (c *jsonCollector) Collect(ch chan<- prometheus.Metric) {
	c.jsonCollect(ch)
}

func (c *jsonCollector) jsonCollect(ch chan<- prometheus.Metric) {
	stats, labels, err := getNftDataFromJSON(*nftdata)
	if err != nil {
		close(ch)
		return
	}
	for _, s := range stats {
		var lvs []string
		for _, ln := range labels {
			if lv, ok := s.Fields[ln]; ok {
				lvs = append(lvs, lv)
			}
		}
		ch <- prometheus.MustNewConstMetric(
			c.packetsTotal,
			prometheus.CounterValue,
			float64(s.Packets),
			lvs...)
		ch <- prometheus.MustNewConstMetric(
			c.bytesTotal,
			prometheus.CounterValue,
			float64(s.Bytes),
			lvs...)
	}
}

func getNftDataFromJSON(path string) ([]Stat, []string, error) {
	var stats []Stat
	labelmap := make(map[string]bool)
	data, err := os.ReadFile(path)
	if err != nil {
		return stats, []string{}, fmt.Errorf("could not read JSON file at %v: %w", path, err)
	}
	err = json.Unmarshal(data, &stats)
	if err != nil {
		log.Printf("Could not unmarshal NFT JSON data: %s", err)
		return stats, []string{}, err
	}
	for _, s := range stats {
		for l := range s.Fields {
			labelmap[l] = true
		}
	}
	labels := make([]string, 0, len(labelmap))
	for k := range labelmap {
		labels = append(labels, k)
	}
	sort.Strings(labels)
	return stats, labels, nil
}

func forkWebserver() *exec.Cmd {
	pid := os.Getpid()
	ownPath := os.Args[0]
	log.Printf("[%d] fork+exec %s -w -jsonfile %s -listen %s -timeout %s", pid, ownPath, *nftdata, *listen, timeout.String())
	c := exec.Command(ownPath, "-w", "-jsonfile", *nftdata, "-listen", *listen, "-timeout", timeout.String())
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	err := c.Start() // implies fork&exec
	if err != nil {
		log.Printf("Could not fork+exec webserver process: %s", err)
		os.Exit(-1)
	}
	return c
}
