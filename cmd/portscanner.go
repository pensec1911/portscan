package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pensec1911/portscan/internal/scanner"
)

const (
	dialTimeout      = 500 * time.Millisecond
	discoveryTimeout = 400 * time.Millisecond
	workers          = 500 // unter `ulimit -n` bleiben (oft 1024)
	discoveryWorkers = 128
	minPrefixBits    = 16 // größer als /16 wird abgelehnt
)

// Ports that are probed during host discovery. If any of these ports is open or closed (not filtered), the host is considered alive.
var discoveryPorts = []int{80, 443, 22, 445, 139, 8080, 3389, 53, 21, 23, 1716, 5000, 8443}

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

// ---------- Single Port ----------

// ---------- Port-Scan eines Hosts ----------

// scanPorts scanns alle Ports 1-65535 auf einem Host mit mehreren Goroutinen.
func scanPorts(ip string) (open []int, failed int, firstErr error) {
	ports := make(chan int, workers)
	results := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				state, err := scanner.ProbePort(ip, p, dialTimeout)
				if err != nil {
					mu.Lock()
					failed++
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				if state == scanner.StateOpen {
					results <- p
				}
			}
		}()
	}

	go func() {
		for p := 1; p <= 65535; p++ {
			ports <- p
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)
	return open, failed, firstErr
}

func printHostResult(ip string, open []int, failed int, firstErr error, took time.Duration) {
	if len(open) == 0 {
		fmt.Printf("  %-15s no open TCP ports (%s)\n", ip, took.Round(time.Millisecond))
	} else {
		strs := make([]string, len(open))
		for i, p := range open {
			strs[i] = strconv.Itoa(p)
		}
		fmt.Printf("  %-15s open: %s (%s)\n", ip, strings.Join(strs, ", "), took.Round(time.Millisecond))
	}
	if failed > 0 {
		fmt.Printf("  %-15s warning: %d ports not checked (first error: %v)\n", "", failed, firstErr)
	}
}

// ---------- Subnet / Host-Discovery ----------

// hostsInPrefix lists all IP addresses in a given prefix, excluding the network and broadcast addresses for prefixes larger than /30.
func hostsInPrefix(prefix netip.Prefix) []netip.Addr {
	prefix = prefix.Masked()
	var hosts []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		hosts = append(hosts, addr)
	}
	// Netz- und Broadcast-Adresse weglassen (außer bei /31 und /32)
	if prefix.Bits() <= 30 && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts
}

// isHostAlive checks if a host is alive by probing several common ports. If any port is open or closed (not filtered), the host is considered alive.
// Open ports indicate that the host is reachable, while closed ports indicate that the host is reachable but the specific port is not open. Filtered ports (no response) do not provide conclusive evidence of the host's status.
func isHostAlive(ip string) bool {
	for _, p := range discoveryPorts {
		state, _ := scanner.ProbePort(ip, p, discoveryTimeout)
		if state == scanner.StateOpen || state == scanner.StateClosed {
			return true
		}
	}
	return false
}

// arp reads the ARP table and returns a map of IP addresses that are alive according to ARP.
func arpHosts(prefix netip.Prefix) map[string]bool {
	found := map[string]bool{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return found
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // Kopfzeile überspringen
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// IP  HWtype  Flags  HWaddress  Mask  Device
		if len(fields) < 4 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		if fields[2] == "0x2" && fields[3] != "00:00:00:00:00:00" { // 0x2 = vollständiger Eintrag
			found[fields[0]] = true
		}
	}
	return found
}

func discoverHosts(prefix netip.Prefix) []string {
	hosts := hostsInPrefix(prefix)
	fmt.Printf("Discovering hosts in %s (%d addresses)...\n", prefix.Masked(), len(hosts))

	jobs := make(chan string, discoveryWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	alive := map[string]bool{}

	for i := 0; i < discoveryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if isHostAlive(ip) {
					mu.Lock()
					alive[ip] = true
					mu.Unlock()
				}
			}
		}()
	}
	for _, h := range hosts {
		jobs <- h.String()
	}
	close(jobs)
	wg.Wait()

	// Die Verbindungsversuche haben ARP-Anfragen ausgelöst → Tabelle auswerten
	for ip := range arpHosts(prefix) {
		alive[ip] = true
	}

	list := make([]string, 0, len(alive))
	for ip := range alive {
		list = append(list, ip)
	}
	sort.Slice(list, func(i, j int) bool {
		a, _ := netip.ParseAddr(list[i])
		b, _ := netip.ParseAddr(list[j])
		return a.Less(b)
	})
	return list
}

func scanSubnet(prefix netip.Prefix) {
	start := time.Now()
	alive := discoverHosts(prefix)
	if len(alive) == 0 {
		fmt.Println("No hosts found")
		return
	}
	fmt.Printf("Found %d hosts: %s\n\n", len(alive), strings.Join(alive, ", "))

	fmt.Println("Scanning ports 1-65535 on each host...")
	for _, ip := range alive {
		t := time.Now()
		open, failed, firstErr := scanPorts(ip)
		printHostResult(ip, open, failed, firstErr, time.Since(t))
	}
	fmt.Printf("\nDone in %s\n", time.Since(start).Round(time.Millisecond))
}

// ---------- Eingabe ----------

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
		fmt.Printf("Scanning ports 1-65535 on %s with %d workers...\n", t.ip, workers)
		start := time.Now()
		open, failed, firstErr := scanPorts(t.ip)
		printHostResult(t.ip, open, failed, firstErr, time.Since(start))

	default:
		state, err := scanner.ProbePort(t.ip, t.port, dialTimeout)
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
