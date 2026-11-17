package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

type PortState int

const (
	StateOpen PortState = iota
	StateClosed
	StateFiltered
)

// ProbePort tries to connect to a given IP and port with a timeout. It returns the port state (open, closed, filtered) and an error if an unexpected error occurs (e.g., "too many open files").
// err is only returned for unexpected errors, not for normal port states.
func ProbePort(ip string, port int, timeout time.Duration) (PortState, error) {
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err == nil {
		conn.Close()
		return StateOpen, nil
	}

	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED): // RST → Port zu, aber Host lebt
		return StateClosed, nil
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return StateFiltered, nil
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return StateFiltered, nil
	default:
		return StateFiltered, err
	}
}
