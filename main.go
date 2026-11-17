package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout = 500 * time.Millisecond
	workers     = 500 // unter `ulimit -n` bleiben (oft 1024)
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

// isPortOpen gibt zurück, ob der Port offen ist.
// err ist nur gesetzt bei unerwarteten Fehlern (z.B. "too many open files"),
// nicht bei "connection refused" (closed) oder Timeout (filtered).
func isPortOpen(ip string, port int) (bool, error) {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err == nil {
		conn.Close()
		return true, nil
	}

	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED): // closed
		return false, nil
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout(): // filtered
		return false, nil
	default:
		return false, err
	}
}

func checkAllPorts(ip string) {
	const startPort, endPort = 1, 65535
	fmt.Printf("Scanning ports %d to %d with %d workers...\n", startPort, endPort, workers)
	start := time.Now()

	ports := make(chan int, workers)
	results := make(chan int)
	var wg sync.WaitGroup

	var mu sync.Mutex
	var unexpected []error

	// Worker starten
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				open, err := isPortOpen(ip, p)
				if err != nil {
					mu.Lock()
					unexpected = append(unexpected, err)
					mu.Unlock()
					continue
				}
				if open {
					results <- p
				}
			}
		}()
	}

	// Ports verteilen
	go func() {
		for p := startPort; p <= endPort; p++ {
			ports <- p
		}
		close(ports)
	}()

	// results schließen, sobald alle Worker fertig sind
	go func() {
		wg.Wait()
		close(results)
	}()

	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)

	for _, p := range open {
		fmt.Printf("Port %d is open\n", p)
	}
	if len(open) == 0 {
		fmt.Println("No open ports found")
	}
	fmt.Printf("Done in %s\n", time.Since(start).Round(time.Millisecond))

	if len(unexpected) > 0 {
		fmt.Printf("Warning: %d ports could not be checked (first error: %v)\n",
			len(unexpected), unexpected[0])
	}
}

// parseInput akzeptiert "1.2.3.4" oder "1.2.3.4:80".
func parseInput(input string) (ip string, port string, err error) {
	if !strings.Contains(input, ":") {
		return input, "", nil
	}
	return net.SplitHostPort(input)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var ip, port string

	for {
		fmt.Print("Enter IPv4[:Port]: ")
		if !scanner.Scan() { // EOF (Ctrl+D) oder Lesefehler
			fmt.Println()
			return
		}
		input := strings.TrimSpace(scanner.Text())

		var err error
		ip, port, err = parseInput(input)
		if err != nil {
			fmt.Println("Invalid input:", err)
			continue
		}
		if !isValidIPv4(ip) {
			fmt.Println("Invalid IPv4 address")
			continue
		}
		break
	}

	if port == "" {
		checkAllPorts(ip)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil || !isValidPort(portInt) {
		fmt.Println("Invalid port")
		return
	}

	open, err := isPortOpen(ip, portInt)
	switch {
	case err != nil:
		fmt.Println("Error:", err)
	case open:
		fmt.Printf("Port %d is open\n", portInt)
	default:
		fmt.Printf("Port %d is closed or filtered\n", portInt)
	}
}
