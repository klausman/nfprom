//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

var (
	nftable  = flag.String("table", "firewall", "Nftables table to use")
	nftchain = flag.String("chain", "accounting", "Nftables chain to use")
)

func extractUdata(udata []byte) string {
	if len(udata) < 2 {
		return ""
	}
	typ := udata[0]
	if typ != 0 {
		return ""
	}
	// Type 0 is a comment
	length := int(udata[1])
	if len(udata) < length+2 {
		return ""
	}
	data := string(udata[2 : length+1])
	return data
}

func exportNftForever() {
	conn, err := nftables.New()
	if err != nil {
		log.Printf("Could not connect to Netfilter/Netlink endpoint: %s", err)
		os.Exit(-1)
	}
	for {
		table := nftables.Table{Name: *nftable}
		chain := nftables.Chain{Name: *nftchain}
		rules, err := conn.GetRules(&table, &chain)
		if err != nil {
			log.Printf("Could not collect chain %s from table %s: %s", *nftchain, *nftable, err)
			os.Exit(-1)
		}
		labelmap := make(map[string]bool)
		stats := make([]Stat, 0, len(rules))
		for _, rule := range rules {
			s := NewStat()
			ud := extractUdata(rule.UserData)
			if !strings.HasPrefix(ud, "nft(") || !strings.HasSuffix(ud, ")") {
				continue
			}
			nftdata := ud[4 : len(ud)-1]
			toks := strings.Split(nftdata, ";")
			for _, tok := range toks {
				kv := strings.Split(tok, "=")
				if len(kv) != 2 {
					continue
				}
				s.Fields[kv[0]] = kv[1]
				s.Labels = append(s.Labels, kv[0])
				labelmap[kv[0]] = true
			}
			sort.Strings(s.Labels)
			for _, ex := range rule.Exprs {
				if ext, ok := ex.(*expr.Counter); ok {
					s.Bytes = ext.Bytes
					s.Packets = ext.Packets
				}
			}
			stats = append(stats, s)
		}
		labels := make([]string, 0, len(labelmap))
		for k := range labelmap {
			labels = append(labels, k)
		}
		sort.Strings(labels)
		err = writeJSON(stats, *nftdata)
		if err != nil {
			os.Exit(-1)
		}
		time.Sleep(15 * time.Second)
	}
}

func writeJSON(stats []Stat, path string) error {
	data, err := json.Marshal(stats)
	if err != nil {
		log.Printf("Could not marshal stats to JSON: %s", err)
		return err
	}
	// #nosec G306
	err = os.WriteFile(path, data, 0o644)
	if err != nil {
		log.Printf("Could not writ JSON to file '%s': %s", path, err)
	}
	return err
}
