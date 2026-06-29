package file

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	pqc "github.com/helsingin/pqc"
)

const keySetSchema = "pqc.file-keyset.v1"

type Store struct {
	dir string
}

type keySet struct {
	Schema   string          `json:"schema"`
	ID       string          `json:"id"`
	Versions []pqc.KeyRecord `json:"versions"`
}

func New(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func DefaultDir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("PQC_STORE_DIR")); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pqc", "keys"), nil
}

func (s *Store) Put(ctx context.Context, record pqc.KeyRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecord(record); err != nil {
		return err
	}

	set, err := s.read(record.ID)
	if errors.Is(err, pqc.ErrKeyNotFound) {
		if record.Version != 1 {
			return fmt.Errorf("first key version must be 1")
		}
		set = keySet{Schema: keySetSchema, ID: record.ID}
	} else if err != nil {
		return err
	}

	if set.ID != record.ID {
		return fmt.Errorf("keyset id mismatch: %q != %q", set.ID, record.ID)
	}
	if len(set.Versions) > 0 {
		latest := set.Versions[len(set.Versions)-1]
		if record.Algorithm != latest.Algorithm {
			return fmt.Errorf("cannot change key algorithm from %s to %s", latest.Algorithm, record.Algorithm)
		}
		if record.Version != latest.Version+1 {
			return fmt.Errorf("next key version must be %d", latest.Version+1)
		}
	}
	for _, existing := range set.Versions {
		if existing.Version == record.Version {
			return fmt.Errorf("%w: %s version %d", pqc.ErrKeyExists, record.ID, record.Version)
		}
	}

	set.Versions = append(set.Versions, cloneRecord(record))
	return s.write(ctx, set)
}

func (s *Store) Get(ctx context.Context, id string) (pqc.KeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return pqc.KeyRecord{}, err
	}
	set, err := s.read(id)
	if err != nil {
		return pqc.KeyRecord{}, err
	}
	if len(set.Versions) == 0 {
		return pqc.KeyRecord{}, fmt.Errorf("%w: %s", pqc.ErrKeyNotFound, id)
	}
	return cloneRecord(set.Versions[len(set.Versions)-1]), nil
}

func (s *Store) GetVersion(ctx context.Context, id string, version int) (pqc.KeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return pqc.KeyRecord{}, err
	}
	set, err := s.read(id)
	if err != nil {
		return pqc.KeyRecord{}, err
	}
	for _, record := range set.Versions {
		if record.Version == version {
			return cloneRecord(record), nil
		}
	}
	return pqc.KeyRecord{}, fmt.Errorf("%w: %s version %d", pqc.ErrKeyNotFound, id, version)
}

func (s *Store) List(ctx context.Context) ([]pqc.KeyMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	keys := make([]pqc.KeyMetadata, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var set keySet
		if err := json.Unmarshal(data, &set); err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		if len(set.Versions) == 0 {
			continue
		}
		latest := set.Versions[len(set.Versions)-1]
		keys = append(keys, pqc.KeyMetadata{
			ID:        latest.ID,
			Algorithm: latest.Algorithm,
			Use:       latest.Use,
			Version:   latest.Version,
			CreatedAt: latest.CreatedAt,
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ID < keys[j].ID
	})
	return keys, nil
}

func (s *Store) read(id string) (keySet, error) {
	path := s.path(id)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return keySet{}, fmt.Errorf("%w: %s", pqc.ErrKeyNotFound, id)
	}
	if err != nil {
		return keySet{}, err
	}
	var set keySet
	if err := json.Unmarshal(data, &set); err != nil {
		return keySet{}, err
	}
	if set.Schema != keySetSchema {
		return keySet{}, fmt.Errorf("unsupported keyset schema %q", set.Schema)
	}
	return set, nil
}

func (s *Store) write(ctx context.Context, set keySet) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	path := s.path(set.ID)
	tmp, err := os.CreateTemp(s.dir, ".tmp-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (s *Store) path(id string) string {
	name := base64.RawURLEncoding.EncodeToString([]byte(id)) + ".json"
	return filepath.Join(s.dir, name)
}

func validateRecord(record pqc.KeyRecord) error {
	if record.ID == "" {
		return fmt.Errorf("key id is required")
	}
	if record.Version < 1 {
		return fmt.Errorf("key version must be positive")
	}
	use, err := record.Algorithm.Use()
	if err != nil {
		return err
	}
	if record.Use != use {
		return fmt.Errorf("key use %q does not match algorithm %s", record.Use, record.Algorithm)
	}
	if len(record.PublicKey) == 0 {
		return fmt.Errorf("public key is required")
	}
	if len(record.PrivateKey) == 0 {
		return fmt.Errorf("private key is required")
	}
	return nil
}

func cloneRecord(record pqc.KeyRecord) pqc.KeyRecord {
	record.PublicKey = append([]byte(nil), record.PublicKey...)
	record.PrivateKey = append([]byte(nil), record.PrivateKey...)
	return record
}
