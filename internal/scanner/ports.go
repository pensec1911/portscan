package scanner

import (
	"sort"
	"sync"
	"time"
)

const (
	DialTimeout = 500 * time.Millisecond
	Workers     = 500 // unter `ulimit -n` bleiben (oft 1024)
)

type Result struct {
	IP       string
	Open     []int
	Failed   int
	FirstErr error
}

// ScanPorts scanns alle Ports 1-65535 auf einem Host mit mehreren Goroutinen.
func ScanPorts(ip string) Result {
	res := Result{IP: ip}
	ports := make(chan int, Workers)
	results := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				state, err := ProbePort(ip, p, DialTimeout)
				if err != nil {
					mu.Lock()
					res.Failed++
					if res.FirstErr == nil {
						res.FirstErr = err
					}
					mu.Unlock()
					continue
				}
				if state == StateOpen {
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
		res.Open = append(res.Open, p)
	}
	sort.Ints(res.Open)
	return res
}
