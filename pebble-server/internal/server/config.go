package server

import "time"

// Config holds runtime settings for the UDP server.
type Config struct {
	DBPath       string
	ListenAddr   string
	Workers      int
	Policy       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxScanKeys  int
	LogDir       string
	ResultsDir   string
}

// Validate normalises and validates the config.
func (c *Config) Validate() error {
	if c.DBPath == "" {
		return ErrInvalidConfig("db_path must be set")
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:9000"
	}
	if c.Workers <= 0 {
		c.Workers = 1
	}
	if c.MaxScanKeys <= 0 {
		c.MaxScanKeys = 1000
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 2 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 2 * time.Second
	}
	return nil
}
