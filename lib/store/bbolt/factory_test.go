package bbolt

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func TestFactoryValid(t *testing.T) {
	f := Factory{}

	t.Run("bad config", func(t *testing.T) {
		if err := f.Valid(json.RawMessage(`}`)); err == nil {
			t.Error("wanted parsing failure but got a successful result")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			cfg  Config
			err  error
		}{
			{
				name: "missing path",
				cfg:  Config{},
				err:  ErrMissingPath,
			},
			{
				name: "unwritable folder",
				cfg: Config{
					Path: filepath.Join("/", "testdb"),
				},
				err: ErrCantWriteToPath,
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				data, err := json.Marshal(tt.cfg)
				if err != nil {
					t.Fatal(err)
				}

				if err := f.Valid(json.RawMessage(data)); !errors.Is(err, tt.err) {
					t.Error(err)
				}
			})
		}
	})
}
