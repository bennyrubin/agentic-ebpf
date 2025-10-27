package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cockroachdb/pebble"
)

func main() {
	var (
		dbPath    = flag.String("db", "./pebble.data", "directory for Pebble data files")
		numKeys   = flag.Int("keys", 1000, "number of key/value pairs to create")
		valueSize = flag.Int("value-bytes", 256, "size of each value in bytes")
		keyPrefix = flag.String("key-prefix", "key", "string prefix to use for generated keys")
		destroy   = flag.Bool("destroy", false, "remove any existing Pebble data before loading")
	)
	flag.Parse()

	if *numKeys <= 0 {
		log.Fatalf("keys must be positive")
	}
	if *valueSize <= 0 {
		log.Fatalf("value-bytes must be positive")
	}

	absPath, err := filepath.Abs(*dbPath)
	if err != nil {
		log.Fatalf("resolve db path: %v", err)
	}

	if *destroy {
		log.Printf("Destroying existing Pebble DB at %s", absPath)
		if err := os.RemoveAll(absPath); err != nil {
			log.Fatalf("destroy db: %v", err)
		}
	}

	db, err := pebble.Open(absPath, &pebble.Options{})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	log.Printf("Populating %d keys (value size %d bytes)", *numKeys, *valueSize)

	value := make([]byte, *valueSize)
	encoded := make([]byte, hex.EncodedLen(len(value)))

	start := time.Now()
	for i := 0; i < *numKeys; i++ {
		key := fmt.Sprintf("%s%08d", *keyPrefix, i)
		if _, err := rand.Read(value); err != nil {
			log.Fatalf("rand read: %v", err)
		}
		hex.Encode(encoded, value)
		if err := db.Set([]byte(key), encoded, pebble.Sync); err != nil {
			log.Fatalf("write key %s: %v", key, err)
		}
		if i%1000 == 0 {
			log.Printf("Loaded %d keys", i)
		}
	}

	log.Printf("Database ready at %s (duration %s)", absPath, time.Since(start))

	if info, err := os.Stat(absPath); err == nil {
		log.Printf("Data directory entry size: %d bytes", info.Size())
	}
}
