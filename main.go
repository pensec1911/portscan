package main

import (
	bufio "bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

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

func isPortOpen(ip string, port int) bool {
	target := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	port := "" // Default port to check
	text := ""
	for {
		fmt.Print("Enter IPv4:Port ")
		scanner.Scan()
		text = strings.TrimSpace(scanner.Text())
		if strings.Contains(text, ":") {
			port = strings.Split(text, ":")[1]
			text = strings.Split(text, ":")[0]
		}
		if !isValidIPv4(text) {
			fmt.Println("Invalid IPv4 address")
			continue
		}
		break
	}
	fmt.Println("You entered a valid IPv4 address:", text, "and port:", port)
	if port == "" {
		port = "8080" // Default port
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println("Invalid port")
		return
	}
	if !isValidPort(portInt) {
		fmt.Println("Invalid port")
		return
	}
	if isPortOpen(text, portInt) {
		fmt.Println("Port is open")
	} else {
		fmt.Println("Port is closed or filtered")
	}
}
