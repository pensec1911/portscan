package scanner

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

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
