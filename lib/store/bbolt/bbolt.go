package bbolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TecharoHQ/anubis/lib/store"
	"go.etcd.io/bbolt"
)

var (
	ErrBucketDoesNotExist = errors.New("bbolt: bucket does not exist")
	ErrNotExists          = errors.New("bbolt: value does not exist in store")
)

type Item struct {
	Data    []byte    `json:"data"`
	Expires time.Time `json:"expires"`
}

type Store struct {
	bucket []byte
	bdb    *bbolt.DB
}

func (s *Store) Delete(ctx context.Context, key string) error {
	return s.bdb.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(s.bucket)
		if bkt == nil {
			return fmt.Errorf("%w: %q", ErrBucketDoesNotExist, string(s.bucket))
		}

		if bkt.Get([]byte(key)) == nil {
			return fmt.Errorf("%w: %q", ErrNotExists, key)
		}

		return bkt.Delete([]byte(key))
	})
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	var i Item

	if err := s.bdb.View(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(s.bucket)
		if bkt == nil {
			return fmt.Errorf("%w: %q", ErrBucketDoesNotExist, string(s.bucket))
		}

		bucketData := bkt.Get([]byte(key))
		if bucketData == nil {
			return fmt.Errorf("%w: %q", store.ErrNotFound, key)
		}

		if err := json.Unmarshal(bucketData, &i); err != nil {
			return fmt.Errorf("%w: %w", store.ErrCantDecode, err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if time.Now().After(i.Expires) {
		go s.Delete(context.Background(), key)
		return nil, fmt.Errorf("%w: %q", store.ErrNotFound, key)
	}

	return i.Data, nil
}

func (s *Store) Set(ctx context.Context, key string, value []byte, expiry time.Duration) error {
	i := Item{
		Data:    value,
		Expires: time.Now().Add(expiry),
	}

	data, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrCantEncode, err)
	}

	return s.bdb.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(s.bucket)
		if bkt == nil {
			return fmt.Errorf("%w: %q", ErrBucketDoesNotExist, string(s.bucket))
		}

		return bkt.Put([]byte(key), data)
	})
}

func (s *Store) cleanup(ctx context.Context) error {
	now := time.Now()

	return s.bdb.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(s.bucket)
		if bkt == nil {
			return fmt.Errorf("cache bucket %q does not exist", string(s.bucket))
		}

		return bkt.ForEach(func(k, v []byte) error {
			var i Item

			data := bkt.Get(k)
			if data == nil {
				return fmt.Errorf("%s in Cache bucket does not exist???", string(k))
			}

			if err := json.Unmarshal(data, &i); err != nil {
				return fmt.Errorf("can't unmarshal data at key %s: %w", string(k), err)
			}

			if now.After(i.Expires) {
				return bkt.Delete(k)
			}

			return nil
		})
	})

}

func (s *Store) cleanupThread(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.cleanup(ctx); err != nil {
				slog.Error("error during bbolt cleanup", "err", err)
			}
		}
	}
}
