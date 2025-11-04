package server

import "time"

// Config holds runtime settings for the UDP server.
type Config struct {
	ListenAddr   string
	Workers      int
	Policy       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxScanKeys  int
	LogDir       string
	ResultsDir   string
	GetDelay     time.Duration
	ScanDelay    time.Duration
}

// Validate normalises and validates the config.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:9000"
	}
	if c.Workers <= 0 {
		c.Workers = 1
	}
	if c.MaxScanKeys <= 0 {
		c.MaxScanKeys = 100000
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 2 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 2 * time.Second
	}
	if c.GetDelay <= 0 {
		c.GetDelay = 10 * time.Microsecond
	}
	if c.ScanDelay <= 0 {
		c.ScanDelay = 2 * time.Millisecond
	}
	return nil
}
