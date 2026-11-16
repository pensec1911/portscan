package main

import (
	bufio "bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func isValidIPv4(ip string) bool {
	adr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return adr.Is4()
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	text := ""
	for {
		fmt.Print("Enter IPv4: ")
		scanner.Scan()
		text := strings.TrimSpace(scanner.Text())
		if !isValidIPv4(text) {
			fmt.Println("Invalid IPv4 address")
			continue
		}
		break
	}
	fmt.Println("You entered a valid IPv4 address:", text)
}
