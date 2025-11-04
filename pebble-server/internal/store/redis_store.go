package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	keyIndexName        = "__pebble:index:keys"
	defaultKeyPrefix    = "key"
	defaultValuePattern = "value:"
)

// ErrNotFound indicates the requested key does not exist in the store.
var ErrNotFound = errors.New("key not found")

// Config captures the tunables for the embedded Redis store.
type Config struct {
	DB        int
	Keyspace  int
	ValueSize int
	ScanCount int
	KeyPrefix string
}

// Entry represents a key/value pair returned from a scan.
type Entry struct {
	Key   string
	Value string
}

// RedisStore wraps an in-process Redis instance (miniredis) and a client.
type RedisStore struct {
	cfg    Config
	server *miniredis.Miniredis
	client *redis.Client

	scanMu sync.Mutex
}

// NewRedisStore starts an embedded Redis server and seeds it according to cfg.
func NewRedisStore(ctx context.Context, cfg Config) (*RedisStore, error) {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = defaultKeyPrefix
	}
	if cfg.ScanCount < 0 {
		cfg.ScanCount = 0
	}

	minisrv, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("start miniredis: %w", err)
	}

	opts := &redis.Options{
		Addr: minisrv.Addr(),
		DB:   cfg.DB,
	}
	client := redis.NewClient(opts)

	store := &RedisStore{
		cfg:    cfg,
		server: minisrv,
		client: client,
	}
	if err := store.seedKeyspace(ctx); err != nil {
		client.Close()
		minisrv.Close()
		return nil, err
	}
	return store, nil
}

// Close shuts down the embedded Redis server and client.
func (s *RedisStore) Close() error {
	var firstErr error
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			firstErr = err
		}
	}
	if s.server != nil {
		s.server.Close()
	}
	return firstErr
}

// Get retrieves a value for the provided key.
func (s *RedisStore) Get(ctx context.Context, key string) (string, error) {
	res, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return res, nil
}

// Set inserts or updates a key/value pair.
func (s *RedisStore) Set(ctx context.Context, key, value string) error {
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, key, value, 0)
	pipe.ZAdd(ctx, keyIndexName, redis.Z{Score: 0, Member: key})
	_, err := pipe.Exec(ctx)
	return err
}

// Scan returns up to limit key/value pairs beginning at startKey.
// The operation is guarded by a mutex to ensure single-threaded iteration.
func (s *RedisStore) Scan(ctx context.Context, startKey string, limit int) ([]Entry, error) {
	if limit <= 0 {
		if s.cfg.ScanCount <= 0 {
			return nil, nil
		}
		limit = s.cfg.ScanCount
	}
	if s.cfg.ScanCount > 0 && limit > s.cfg.ScanCount {
		limit = s.cfg.ScanCount
	}

	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	min := "-"
	if startKey != "" {
		min = "[" + startKey
	}

	keys, err := s.client.ZRangeByLex(ctx, keyIndexName, &redis.ZRangeBy{
		Min:   min,
		Max:   "+",
		Count: int64(limit),
	}).Result()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}

	rawValues, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	results := make([]Entry, 0, len(keys))
	for i, key := range keys {
		if rawValues[i] == nil {
			continue
		}
		switch val := rawValues[i].(type) {
		case string:
			results = append(results, Entry{Key: key, Value: val})
		case []byte:
			results = append(results, Entry{Key: key, Value: string(val)})
		default:
			results = append(results, Entry{Key: key, Value: fmt.Sprint(val)})
		}
	}
	return results, nil
}

func (s *RedisStore) seedKeyspace(ctx context.Context) error {
	if s.cfg.Keyspace <= 0 {
		return nil
	}

	valueSize := s.cfg.ValueSize
	if valueSize < 0 {
		valueSize = 0
	}

	const batchSize = 1024
	batch := s.client.Pipeline()
	cmdsInBatch := 0

	for i := 0; i < s.cfg.Keyspace; i++ {
		key := fmt.Sprintf("%s%08d", s.cfg.KeyPrefix, i)
		value := buildValue(key, valueSize)
		batch.Set(ctx, key, value, 0)
		batch.ZAdd(ctx, keyIndexName, redis.Z{Score: 0, Member: key})
		cmdsInBatch += 2

		if (i+1)%batchSize == 0 {
			if err := execBatch(ctx, batch); err != nil {
				return fmt.Errorf("seed pipeline: %w", err)
			}
			cmdsInBatch = 0
		}
	}
	if cmdsInBatch > 0 {
		if err := execBatch(ctx, batch); err != nil {
			return fmt.Errorf("seed pipeline: %w", err)
		}
	}
	return nil
}

func execBatch(ctx context.Context, pipe redis.Pipeliner) error {
	cmds, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	for _, cmd := range cmds {
		if err := cmd.Err(); err != nil && !errors.Is(err, redis.Nil) {
			return err
		}
	}
	return nil
}

func buildValue(key string, size int) string {
	if size <= 0 {
		return key
	}
	if len(key) >= size {
		return key[:size]
	}

	var sb strings.Builder
	sb.Grow(size)
	sb.WriteString(key)
	remaining := size - len(key)
	if remaining <= 0 {
		return sb.String()
	}
	repeat := defaultValuePattern
	for remaining > 0 {
		if remaining < len(repeat) {
			sb.WriteString(repeat[:remaining])
			break
		}
		sb.WriteString(repeat)
		remaining -= len(repeat)
	}
	return sb.String()
}
