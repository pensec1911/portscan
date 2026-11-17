package scanner

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	discoveryTimeout = 400 * time.Millisecond
	discoveryWorkers = 128
)

// Ports that are probed during host discovery. If any of these ports is open or closed (not filtered), the host is considered alive.
var discoveryPorts = []int{80, 443, 22, 445, 139, 8080, 3389, 53, 21, 23, 1716, 5000, 8443}

// HostsInPrefix lists all IP addresses in a given prefix, excluding the network and broadcast addresses for prefixes larger than /30.
func HostsInPrefix(prefix netip.Prefix) []netip.Addr {
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
		state, _ := ProbePort(ip, p, discoveryTimeout)
		if state == StateOpen || state == StateClosed {
			return true
		}
	}
	return false
}

func DiscoverHosts(prefix netip.Prefix) []string {
	hosts := HostsInPrefix(prefix)
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
