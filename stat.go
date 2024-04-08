//go:build linux

package main

import (
	"fmt"
	"strings"
)

// Stat does stat things
type Stat struct {
	Bytes   uint64            `json:"Bytes"`
	Packets uint64            `json:"Packets"`
	Labels  []string          `json:"Labels"`
	Fields  map[string]string `json:"Fields"`
}

func (s Stat) String() string {
	var acc strings.Builder
	for k, v := range s.Fields {
		acc.WriteString(fmt.Sprintf("%s=%s;", k, v))
	}
	acc.WriteString(fmt.Sprintf("By=%d;Pk=%d", s.Bytes, s.Packets))
	return acc.String()
}

// NewStat creates a new Stat object with the Fields map initialized
func NewStat() Stat {
	var s Stat
	s.Fields = make(map[string]string)
	return s
}
