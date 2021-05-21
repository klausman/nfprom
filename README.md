# nfprom -- Export data from NF accounting chain

This is a very simple Go server that exports the packet and byte counters from
an IPTables or NFTables accounting chain. Its intended use case is to have a
separate counting-only chain for all the traffic you want stats on, export it
that data using this tool, scrape it with Prometheus and the do whatever
alerting and graphing you want.

It is *very* simple in what it can do, but does have the advantage of being
pretty light on dependencies:

- Go (https://golang.org/) 
- The Prometheus Golang client bindings
  (https://prometheus.io/docs/instrumenting/clientlibs/)
- IPTables userspace tools (https://netfilter.org/) or NFTables userspace tools
  (https://netfilter.org/projects/nftables/)
- sudo (https://www.sudo.ws/)

The first two are only needed for building `nfprom` from source.

While `nfprom` *can* be run as root, it is strongly discouraged. Note that
whatever user `nfprom` runs as must be allowed to run one of these as root
*without a password*:

- IPTables: `sudo iptables-save -c -t filter`
- NFTables: `sudo nft list chain [addrfamily] [table] [chain]` (where the
  tokens in `[]` depend on your setup, see below)

## Expected chain structure -- IPTables

Here's an example IPTables chain `nfprom` can use:

```
# iptables -nvL prometheus
Chain prometheus (2 references)
 pkts bytes target     prot opt in     out     source               destination
 243K   16M RETURN     tcp  --  *      *       0.0.0.0/0            203.0.113.140        tcp dpt:22
 338K   61M RETURN     tcp  --  *      *       203.0.113.140        0.0.0.0/0            tcp spt:22
 277K  138M RETURN     tcp  --  *      *       0.0.0.0/0            203.0.113.140        tcp dpt:25
 243K   24M RETURN     tcp  --  *      *       203.0.113.140        0.0.0.0/0            tcp spt:25
 225K   18M RETURN     tcp  --  *      *       0.0.0.0/0            203.0.113.140        tcp dpt:80
 212K  393M RETURN     tcp  --  *      *       203.0.113.140        0.0.0.0/0            tcp spt:80
15729 2660K RETURN     tcp  --  *      *       0.0.0.0/0            203.0.113.140        tcp dpt:443
14380   18M RETURN     tcp  --  *      *       203.0.113.140        0.0.0.0/0            tcp spt:443
  39M   40G RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
```

Note that the traffic counting rules have RETURN as their target. This is not
strictly necessary since there is a catchall rule at the end, but it makes
packet filtering a little bit faster. One could have rules without a target,
which just does nothing to the packet, except for counting it and its size.

Also note that the source and destination IPs (203.0.113.140 in this example)
are the addresses of the local machine. This way, we can specifically select
traffic that is tied to this port *on this machine*. Otherwise, we would also
see traffic to other machines on those ports, e.g. SSHing elsewhere as opposed
to traffic going to *this machine's* SSH server.

Naturally, this chain must be hooked up to input and output, so both the
`INPUT` and the `OUTPUT` chain have rules that send all traffic to this chain.
Those rules are near the top of those chains, so all traffic can be counted.
Most importantly, they are *before* any rules that allow packets due to their
conntracking status. Otherwise, we would only count the opening packets of
those connections.

## Expected chain structure -- NFTables

NFTables is similar to the above regarding source/destination ports and
addresses and return verdicts. Note that while the example doesn't show it, you
can have mixed v4 and v6 rules in this table (depending on your kernel config,
that is, i.e. nfprom does not care).

The three last tokens on the command line (`inet`, `firewall`, `accounting`) are
configurable on nfprom's side; they refer to the address family, table and chain
you want to scrape. Note that the `inet` here *may* include *inet6* traffic
depending on setup.

```
$ sudo nft list chain inet firewall accounting
table inet firewall {
	chain accounting {
		ip daddr 203.0.113.140 tcp dport 22 counter packets 10 bytes 436 return
		ip saddr 203.0.113.140 tcp sport 22 counter packets 0 bytes 0 return
		ip daddr 203.0.113.140 tcp dport 25 counter packets 170 bytes 20751 return
		ip saddr 203.0.113.140 tcp sport 25 counter packets 131 bytes 11515 return
		ip daddr 203.0.113.140 tcp dport 80 counter packets 161 bytes 15355 return
		ip saddr 203.0.113.140 tcp sport 80 counter packets 123 bytes 16664 return
		ip daddr 203.0.113.140 tcp dport 443 counter packets 440 bytes 49893 return
		ip saddr 203.0.113.140 tcp sport 443 counter packets 452 bytes 197329 return
		return
	}
}
```

Similar to the IPTables setup, this chain must be referred to in your main
input/output chains, typically early on (*before* allowing established/related
connections). For example:

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

The metrics look the same, no matter whether nfprom runs in IPTables or
NFTables mode.

```
nfprom_bytes_total{address="203.0.113.140/32",direction="in",l2proto="ipv4",l3proto="tcp",port="22"} 242699
nfprom_bytes_total{address="203.0.113.140/32",direction="out",l2proto="ipv4",l3proto="tcp",port="22"} 338274
nfprom_packets_total{address="203.0.113.140/32",direction="in",l2proto="ipv4",l3proto="tcp",port="22"} 1.6223817e+07
nfprom_packets_total{address="203.0.113.140/32",direction="out",l2proto="ipv4",l3proto="tcp",port="22"} 6.1386878e+07
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
Usage of ./nfprom:
  -addr string
    	name:port, ipv4:port or [ipv6]:port to listen on (default ":9830")
  -chain string
    	Netfilter (iptables) chain to monitor  (default "prometheus")
  -ipv4
    	Enable/disable collection of IPv4 stats (iptables mode only) (default true)
  -ipv6
    	Enable/disable collection of IPv6 stats (iptables mode only)
  -mode string
    	Mode to run in, one of 'ipt' or 'nft' (default "ipt")
  -namespace string
    	Namespace (prefix) to use for Prometheus metrics (default "nfprom")
  -nfta string
    	Address family to use for nftables (default "inet")
  -nftc string
    	Nftables chain to use (default "accounting")
  -nftt string
    	Nftables table to use (default "firewall")
```

The parameters should be pretty obvious in what they do.

## Automatically starting at system boot

The `init/` subdirectory contains files for OpenRC and SystemD that can be used
to start `nfprom` on system boot. These are meant as *examples* and may need
tweaking depending on your distribution of choice.
