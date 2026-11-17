package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	minPrefixBits = 16 // größer als /16 wird abgelehnt
)

// ---------- Validation ----------

func isValidIPv4(ip string) bool {
	adr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return adr.Is4()
}

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

type target struct {
	ip     string
	port   int          // 0 = alle Ports
	prefix netip.Prefix // gesetzt bei Subnetz-Scan
}

// parseInput akzeptiert "1.2.3.4", "1.2.3.4:80" oder "192.168.178.0/24".
func parseInput(input string) (target, error) {
	var t target

	if strings.Contains(input, "/") {
		prefix, err := netip.ParsePrefix(input)
		if err != nil || !prefix.Addr().Is4() {
			return t, fmt.Errorf("invalid IPv4 subnet")
		}
		if prefix.Bits() < minPrefixBits {
			return t, fmt.Errorf("subnet too large, max /%d", minPrefixBits)
		}
		t.prefix = prefix
		return t, nil
	}

	host, port := input, ""
	if strings.Contains(input, ":") {
		var err error
		host, port, err = net.SplitHostPort(input)
		if err != nil {
			return t, err
		}
	}
	if !isValidIPv4(host) {
		return t, fmt.Errorf("invalid IPv4 address")
	}
	t.ip = host

	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || !isValidPort(p) {
			return t, fmt.Errorf("invalid port")
		}
		t.port = p
	}
	return t, nil
}
