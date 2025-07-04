package bbolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TecharoHQ/anubis/lib/store"
	"go.etcd.io/bbolt"
)

var (
	ErrMissingPath     = errors.New("bbolt: path is missing from config")
	ErrCantWriteToPath = errors.New("bbolt: can't write to path")
)

func init() {
	store.Register("bbolt", Factory{})
}

type Factory struct{}

func (Factory) Build(ctx context.Context, data json.RawMessage) (store.Interface, error) {
	var config Config
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, fmt.Errorf("%w: %w", store.ErrBadConfig, err)
	}

	if err := config.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", store.ErrBadConfig, err)
	}

	if config.Bucket == "" {
		config.Bucket = "anubis"
	}

	bdb, err := bbolt.Open(config.Path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("can't open bbolt database %s: %w", config.Path, err)
	}

	if err := bdb.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(config.Bucket)); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("can't create bbolt bucket %q: %w", config.Bucket, err)
	}

	result := &Store{
		bdb:    bdb,
		bucket: []byte(config.Bucket),
	}

	go result.cleanupThread(ctx)

	return result, nil
}

func (Factory) Valid(data json.RawMessage) error {
	var config Config
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return fmt.Errorf("%w: %w", store.ErrBadConfig, err)
	}

	if err := config.Valid(); err != nil {
		return fmt.Errorf("%w: %w", store.ErrBadConfig, err)
	}

	return nil
}

type Config struct {
	Path   string `json:"path"`
	Bucket string `json:"bucket,omitempty"`
}

func (c Config) Valid() error {
	var errs []error

	if c.Path == "" {
		errs = append(errs, ErrMissingPath)
	} else {
		dir := filepath.Dir(c.Path)
		if err := os.WriteFile(filepath.Join(dir, ".test-file"), []byte(""), 0600); err != nil {
			errs = append(errs, ErrCantWriteToPath)
		}
	}

	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	return nil
}
