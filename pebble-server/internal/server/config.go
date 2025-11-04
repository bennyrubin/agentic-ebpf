package server

import (
	"fmt"
	"time"
)

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
	RedisDB      int
	StoreKeys    int
	StoreValue   int
	StoreScan    int
	StorePrefix  string
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
	if c.GetDelay < 0 {
		return fmt.Errorf("get delay must be non-negative")
	}
	if c.ScanDelay < 0 {
		return fmt.Errorf("scan delay must be non-negative")
	}
	if c.StoreKeys <= 0 {
		c.StoreKeys = 100000
	}
	if c.StoreValue < 0 {
		return fmt.Errorf("store value size must be >= 0")
	}
	if c.StoreScan <= 0 {
		c.StoreScan = 512
	}
	if c.StorePrefix == "" {
		c.StorePrefix = "key"
	}
	return nil
}
