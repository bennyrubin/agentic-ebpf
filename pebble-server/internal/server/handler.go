package server

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

var (
	errUnknownCommand = errors.New("unknown command")
	errMalformed      = errors.New("malformed payload")
)

// parseRequest inspects a wire payload and returns command and arguments.
func parseRequest(payload []byte) (cmd string, args []string, err error) {
	line := strings.TrimSpace(string(bytes.TrimSpace(payload)))
	if line == "" {
		return "", nil, errMalformed
	}
	toks := strings.Fields(line)
	if len(toks) == 0 {
		return "", nil, errMalformed
	}
	cmd = strings.ToUpper(toks[0])
	args = toks[1:]
	switch cmd {
	case "GET":
		if len(args) != 1 && len(args) != 2 {
			return "", nil, fmt.Errorf("GET expects key [request-id]: %w", errMalformed)
		}
	case "SCAN":
		if len(args) != 2 && len(args) != 3 {
			return "", nil, fmt.Errorf("SCAN expects start_key limit [request-id]: %w", errMalformed)
		}
	default:
		return "", nil, errUnknownCommand
	}
	return cmd, args, nil
}
