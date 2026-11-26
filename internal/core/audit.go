package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is a metadata-only record for key manager operations. It must not
// contain key material, plaintext, ciphertext, signatures, or shared secrets.
type AuditEvent struct {
	ID         string       `json:"event_id,omitempty"`
	Outcome    AuditOutcome `json:"outcome,omitempty"`
	Time       time.Time    `json:"time"`
	Operation  string       `json:"operation"`
	KeyID      string       `json:"key_id,omitempty"`
	Algorithm  Algorithm    `json:"algorithm,omitempty"`
	KeyVersion int          `json:"key_version,omitempty"`
	Success    bool         `json:"success"`
	Error      string       `json:"error,omitempty"`
}

// Auditor records metadata-only key manager events.
type Auditor interface {
	Record(context.Context, AuditEvent) error
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(context.Context, AuditEvent) error

func (f AuditorFunc) Record(ctx context.Context, event AuditEvent) error {
	return f(ctx, event)
}

// FileAuditor appends metadata to a local log. It is not an audit replay queue:
// event IDs correlate failures but do not provide deduplication. Use one writer
// per file. Central-service auditing belongs to that service.
type FileAuditor struct {
	mu   sync.Mutex
	path string
}

func NewFileAuditor(path string) (*FileAuditor, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return &FileAuditor{path: path}, nil
}

func (a *FileAuditor) Record(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
