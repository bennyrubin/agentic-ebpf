package server

import "fmt"

// ErrInvalidConfig indicates configuration error.
type ErrInvalidConfig string

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s", string(e))
}
