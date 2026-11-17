package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pensec1911/portscan/internal/scanner"
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

func printHostResult(r scanner.Result, took time.Duration) {
	if len(r.Open) == 0 {
		fmt.Printf("  %-15s no open TCP ports (%s)\n", r.IP, took.Round(time.Millisecond))
	} else {
		strs := make([]string, len(r.Open))
		for i, p := range r.Open {
			strs[i] = strconv.Itoa(p)
		}
		fmt.Printf("  %-15s open: %s (%s)\n", r.IP, strings.Join(strs, ", "), took.Round(time.Millisecond))
	}
	if r.Failed > 0 {
		fmt.Printf("  %-15s warning: %d ports not checked (first error: %v)\n", r.IP, r.Failed, r.FirstErr)
	}
}

func scanSubnet(prefix netip.Prefix) {
	start := time.Now()
	alive := scanner.DiscoverHosts(prefix)
	if len(alive) == 0 {
		fmt.Println("No hosts found")
		return
	}
	fmt.Printf("Found %d hosts: %s\n\n", len(alive), strings.Join(alive, ", "))

	fmt.Println("Scanning ports 1-65535 on each host...")
	for _, ip := range alive {
		t := time.Now()
		r := scanner.ScanPorts(ip)
		printHostResult(r, time.Since(t))
	}
	fmt.Printf("\nDone in %s\n", time.Since(start).Round(time.Millisecond))
}

// ---------- Eingabe ----------

func main() {
	in := bufio.NewScanner(os.Stdin)
	var t target

	for {
		fmt.Print("Enter IPv4[:Port] or subnet (e.g. 192.168.178.0/24): ")
		if !in.Scan() { // EOF (Ctrl+D) oder Lesefehler
			fmt.Println()
			return
		}
		var err error
		t, err = parseInput(strings.TrimSpace(in.Text()))
		if err != nil {
			fmt.Println("Invalid input:", err)
			continue
		}
		break
	}

	switch {
	case t.prefix.IsValid():
		scanSubnet(t.prefix)

	case t.port == 0:
		fmt.Printf("Scanning ports 1-65535 on %s with %d workers...\n", t.ip, scanner.Workers)
		start := time.Now()
		r := scanner.ScanPorts(t.ip)
		printHostResult(r, time.Since(start))

	default:
		state, err := scanner.ProbePort(t.ip, t.port, scanner.DialTimeout)
		switch {
		case err != nil:
			fmt.Println("Error:", err)
		case state == scanner.StateOpen:
			fmt.Printf("Port %d is open\n", t.port)
		case state == scanner.StateClosed:
			fmt.Printf("Port %d is closed\n", t.port)
		default:
			fmt.Printf("Port %d is filtered (no response)\n", t.port)
		}
	}
}
