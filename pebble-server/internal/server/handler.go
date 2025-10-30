package server

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	errUnknownCommand = errors.New("unknown command")
	errMalformed      = errors.New("malformed payload")
)

// parseRequest inspects a wire payload and returns command and arguments.
func parseRequest(payload []byte) (cmd string, args []string, err error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return "", nil, errMalformed
	}
	fields := bytes.Fields(trimmed)
	if len(fields) == 0 {
		return "", nil, errMalformed
	}

	cmdField := fields[0]

	switch {
	case equalFoldASCII(cmdField, "GET"):
		if len(fields) != 2 && len(fields) != 3 {
			return "", nil, fmt.Errorf("GET expects key [request-id]: %w", errMalformed)
		}
		cmd = "GET"
	case equalFoldASCII(cmdField, "SCAN"):
		if len(fields) != 3 && len(fields) != 4 {
			return "", nil, fmt.Errorf("SCAN expects start_key limit [request-id]: %w", errMalformed)
		}
		cmd = "SCAN"
	default:
		return "", nil, errUnknownCommand
	}
	args = make([]string, len(fields)-1)
	for i := 1; i < len(fields); i++ {
		args[i-1] = string(fields[i])
	}
	return cmd, args, nil
}

func equalFoldASCII(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		cb := b[i]
		cs := s[i]
		if 'A' <= cs && cs <= 'Z' {
			cs += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if cb != cs {
			return false
		}
	}
	return true
}
