# nfprom -- Export data from NFTables accounting chain

This is a very simple Go server that exports the packet and byte counters from
an NFTables accounting chain. Its intended use case is to have a separate
counting-only chain for all the traffic you want stats on, export that data
using this tool, scrape it with Prometheus and the do whatever alerting and
graphing you want.

It is *very* simple in what it can do, but does have the advantage of being
pretty light on dependencies:

- Go (https://golang.org/) 
- golang.org/x/sys 
- The Prometheus Golang client bindings
  (https://prometheus.io/docs/instrumenting/clientlibs/)

These are only needed for building `nfprom` from source.

`nfprom` must be run as root or with `CAP_NET_ADMIN` to able to talk to
NFTables via Netlink. The webserver portion of the tool runs with dropped
privileges (configurable). Data is exchanged between the two via a file
that contains JSON data. Its path is of course configurable. Access control
to the file can be done by restricting the access to the directory the file
is in.

## Expected chain structure

Here is an example table structure:

```
  chain accounting {
    ip daddr 203.0.113.140 tcp dport 22  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=SSH;dir=in)"
    ip saddr 203.0.113.140 tcp sport 22  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=SSH;dir=out)"
    ip daddr 203.0.113.140 tcp dport 25  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=SMTP;dir=in)"
    ip saddr 203.0.113.140 tcp sport 25  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=SMTP;dir=out)"
    ip daddr 203.0.113.140 tcp dport 80  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=HTTP;dir=in)"
    ip saddr 203.0.113.140 tcp sport 80  counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=HTTP;dir=out)"
    ip daddr 203.0.113.140 tcp dport 443 counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=HTTPS;dir=in)"
    ip saddr 203.0.113.140 tcp sport 443 counter return comment "nft(l2proto=ipv4;l3proto=tcp;service=HTTPS;dir=out)"
  }
```

By using `saddr`/`daddr` in combination with `sport`/`dport`, we can make sure
we only track what _our_ machine serves on those ports. This way, we avoid also
counting traffic where our machine is the client.

The comment is where `nfprom` extracts the Prometheus metrics labels from. The
names and values there are opaque to `nfprom`, it just re-exports them. Note
that for every such comment, the field names must be the same (you can't have
additional fields on one rule_. This is due to how Prometheus expects metric
labels to behave. You also can't duplicate an exact label set, for the same
reason. In a future version of `nfprom`, there may be convenience functionality
that helps address this.

Naturally, this chain must be referred to in your main input/output chains,
typically early on (*before* allowing established/related connections). For
example:

```
table inet firewall {
	chain incoming {
		type filter hook input priority filter; policy drop;
		jump accounting
		ct state established,related accept
		# [... rest of rules ...]
	}

	chain outgoing {
		# Allow all outgoing traffic
		type filter hook output priority filter; policy accept;
		jump accounting
	}
```

## Nfprom metrics

The parameters of the rules (source, destination, protocol and
source/destination port) are exported by `nfprom`. For example, the counters of
the first rule would look like this when exported as a metric:

```
nfprom_bytes_total{address="203.0.113.140/32",direction="in",l2proto="ipv4",l3proto="tcp",service="SSH"} 242699
nfprom_bytes_total{address="203.0.113.140/32",direction="out",l2proto="ipv4",l3proto="tcp",service="SSH"} 338274
nfprom_packets_total{address="203.0.113.140/32",direction="in",l2proto="ipv4",l3proto="tcp",service="SSH"} 1.6223817e+07
nfprom_packets_total{address="203.0.113.140/32",direction="out",l2proto="ipv4",l3proto="tcp",service="SSH"} 6.1386878e+07
```

## Building

Unpack the tarball (or clone the git repository) and run:

```
$ go build
```

To install, copy the binary (`nfprom`) to whatever location is appropriate
(typically `/usr/local/sbin` or `/usr/local/bin`) and configure your system to
start `nfprom` as is needed (see the section at the end of this file for some
information on that).

## Command line parameters

```
$ nfprom --help
Usage of /store/home/klausman/src/nfprom/nfprom:
  -chain string
        Nftables chain to use (default "accounting")
  -g string
        group to switch to for privilege separation (GID or name) (default "nogroup")
  -jsonfile string
        Path to file for JSON data (default "nftdata.json")
  -listen string
        ip:port to listen on (default ":9830")
  -namespace string
        Namespace (prefix) to use for Prometheus metrics (default "nfprom")
  -table string
        Nftables table to use (default "firewall")
  -timeout duration
        Timeout for webserver reading client request (default 3s)
  -u string
        user to switch to for privilege separation (UID or name) (default "nobody")
  -v    Print version and exit (disregard other flags
  -w    internal flag (do not use)
```

The parameters should be pretty obvious in what they do.

## Automatically starting at system boot

The `init/` subdirectory contains files for OpenRC and SystemD that can be used
to start `nfprom` on system boot. These are meant as *examples* and may need
tweaking depending on your distribution of choice.
