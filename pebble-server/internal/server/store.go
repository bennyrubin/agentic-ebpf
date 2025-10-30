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

// ScanIterator wraps a Pebble iterator for reuse by a single worker goroutine.
type ScanIterator struct {
	store *Store
	iter  *pebble.Iterator
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

// NewScanIterator constructs an iterator that can be reused by a single worker.
func (s *Store) NewScanIterator() (*ScanIterator, error) {
	iter, err := s.db.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}
	return &ScanIterator{
		store: s,
		iter:  iter,
	}, nil
}

// ensure resets the iterator if it was previously invalidated.
func (it *ScanIterator) ensure() error {
	if it == nil {
		return fmt.Errorf("scan iterator is nil")
	}
	if it.iter != nil {
		return nil
	}
	if it.store == nil || it.store.db == nil {
		return fmt.Errorf("scan iterator store closed")
	}
	iter, err := it.store.db.NewIter(nil)
	if err != nil {
		return fmt.Errorf("pebble iter: %w", err)
	}
	it.iter = iter
	return nil
}

// invalidate closes the underlying iterator and marks it as unusable until recreating.
func (it *ScanIterator) invalidate() {
	if it == nil || it.iter == nil {
		return
	}
	_ = it.iter.Close()
	it.iter = nil
}

// Close releases resources held by the iterator.
func (it *ScanIterator) Close() error {
	if it == nil || it.iter == nil {
		return nil
	}
	err := it.iter.Close()
	it.iter = nil
	return err
}

// Scan returns up to limit key/value pairs starting from startKey (inclusive).
// The caller must ensure Scan is not invoked concurrently.
func (it *ScanIterator) Scan(startKey []byte, limit int) ([]ScanEntry, error) {
	if err := it.ensure(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	iter := it.iter
	var positioned bool
	if len(startKey) > 0 {
		positioned = iter.SeekGE(startKey)
	} else {
		positioned = iter.First()
	}
	if !positioned {
		if iterErr := iter.Error(); iterErr != nil {
			it.invalidate()
			return nil, fmt.Errorf("pebble scan: %w", iterErr)
		}
		return nil, nil
	}

	entries := make([]ScanEntry, 0, limit)
	for iter.Valid() && len(entries) < limit {
		key := append([]byte(nil), iter.Key()...)
		val := append([]byte(nil), iter.Value()...)
		entries = append(entries, ScanEntry{
			Key:   string(key),
			Value: val,
		})
		iter.Next()
	}

	if iterErr := iter.Error(); iterErr != nil {
		it.invalidate()
		return nil, fmt.Errorf("pebble scan: %w", iterErr)
	}
	return entries, nil
}

// Get seeks to key and returns the associated value if present.
// The caller must ensure Get is not invoked concurrently.
func (it *ScanIterator) Get(key []byte) ([]byte, bool, error) {
	if err := it.ensure(); err != nil {
		return nil, false, err
	}

	iter := it.iter
	if !iter.SeekGE(key) {
		if iterErr := iter.Error(); iterErr != nil {
			it.invalidate()
			return nil, false, fmt.Errorf("pebble get: %w", iterErr)
		}
		return nil, false, nil
	}
	if !bytes.Equal(iter.Key(), key) {
		return nil, false, nil
	}
	val := append([]byte(nil), iter.Value()...)
	if iterErr := iter.Error(); iterErr != nil {
		it.invalidate()
		return nil, false, fmt.Errorf("pebble get: %w", iterErr)
	}
	return val, true, nil
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
