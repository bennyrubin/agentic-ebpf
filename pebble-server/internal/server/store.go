package server

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
)

const maxScanResponseBytes = 60 << 10 // 60 KiB fits safely within UDP limits

// ScanEntry captures a key/value pair returned by a SCAN operation.
type ScanEntry struct {
	Key   string
	Value []byte
}

// Store wraps a Pebble instance and exposes helper methods tailored to the UDP server.
type Store struct {
	db *pebble.DB
}

// OpenStore opens a Pebble database located at path.
func OpenStore(path string) (*Store, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("open pebble: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases Pebble resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Get retrieves a value by key.
func (s *Store) Get(key []byte) ([]byte, bool, error) {
	val, closer, err := s.db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("pebble get: %w", err)
	}
	defer closer.Close()

	buf := make([]byte, len(val))
	copy(buf, val)
	return buf, true, nil
}

// Scan returns up to limit key/value pairs starting from startKey (inclusive).
func (s *Store) Scan(startKey []byte, limit int) ([]ScanEntry, error) {
	iter, err := s.db.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}

	positioned := false
	if len(startKey) > 0 {
		positioned = iter.SeekGE(startKey)
	} else {
		positioned = iter.First()
	}
	if !positioned {
		if closeErr := iter.Close(); closeErr != nil {
			return nil, fmt.Errorf("pebble iter close: %w", closeErr)
		}
		return nil, nil
	}

	entries := make([]ScanEntry, 0, limit)
	count := 0
	for ; iter.Valid() && count < limit; iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		val := append([]byte(nil), iter.Value()...)
		entries = append(entries, ScanEntry{
			Key:   string(key),
			Value: val,
		})
		count++
	}

	if iterErr := iter.Error(); iterErr != nil {
		iter.Close()
		return nil, fmt.Errorf("pebble scan: %w", iterErr)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("pebble iter close: %w", err)
	}
	return entries, nil
}

// MarshalScan converts a scan result into a wire-friendly representation.
// Returns ok=false if the payload would exceed maxBytes.
func MarshalScan(entries []ScanEntry, maxBytes int) ([]byte, bool) {
	if len(entries) == 0 {
		return []byte("EMPTY"), true
	}
	if maxBytes <= 0 {
		maxBytes = maxScanResponseBytes
	}

	buf := bytes.Buffer{}
	first := true
	for _, entry := range entries {
		additional := len(entry.Key) + 1 + len(entry.Value)
		if !first {
			additional++ // newline separator
		}
		if buf.Len()+additional > maxBytes {
			return nil, false
		}

		if !first {
			buf.WriteByte('\n')
		}
		first = false
		buf.WriteString(entry.Key)
		buf.WriteByte('=')
		buf.Write(entry.Value)
	}
	return buf.Bytes(), true
}
