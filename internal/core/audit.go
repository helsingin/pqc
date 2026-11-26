package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/helsingin/pqc/internal/strictjson"
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

// Auditor records metadata-only key manager events. Implementations must return
// persistence failures. Stable event IDs must be idempotent: identical retries
// succeed without another event, while conflicting ID reuse must fail.
type Auditor interface {
	Record(context.Context, AuditEvent) error
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(context.Context, AuditEvent) error

func (f AuditorFunc) Record(ctx context.Context, event AuditEvent) error {
	return f(ctx, event)
}

// FileAuditor appends one JSON audit event per line.
type FileAuditor struct {
	mu       sync.Mutex
	path     string
	syncFile func(*os.File) error
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
	return &FileAuditor{path: path, syncFile: (*os.File).Sync}, nil
}

// Record serializes writers with a process-local mutex and an OS file lock.
// A successful return includes fsync of the file and its directory. Existing
// events without IDs remain readable; only identified events are deduplicated.
func (a *FileAuditor) Record(ctx context.Context, event AuditEvent) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	event.Time = event.Time.UTC()
	for _, value := range []string{event.ID, event.Operation, event.KeyID, string(event.Algorithm), event.Error} {
		if !utf8.ValidString(value) {
			return fmt.Errorf("audit event contains invalid UTF-8")
		}
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	const maxRecord = 64 << 10
	if len(data)+1 > maxRecord {
		return fmt.Errorf("audit event exceeds 64 KiB")
	}
	if event.ID != "" {
		if len(event.ID) > 256 || event.Operation == "" || event.Time.IsZero() {
			return fmt.Errorf("invalid identified audit event")
		}
		switch event.Outcome {
		case AuditSucceeded:
			if !event.Success {
				return fmt.Errorf("inconsistent audit success")
			}
		case AuditFailed, AuditUnknown:
			if event.Success {
				return fmt.Errorf("inconsistent audit failure")
			}
		default:
			return fmt.Errorf("invalid audit outcome")
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := lockAudit(ctx, file); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlockAudit(file)) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(file, maxRecord)
	var offset int64
	found := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, readErr := reader.ReadSlice('\n')
		if readErr == io.EOF {
			if len(line) > 0 {
				if err := file.Truncate(offset); err != nil {
					return fmt.Errorf("repair incomplete audit tail: %w", err)
				}
			}
			break
		}
		if readErr != nil {
			return fmt.Errorf("read audit record at offset %d: %w", offset, readErr)
		}
		var previous AuditEvent
		if err := strictjson.Decode(line, &previous, false); err != nil {
			return fmt.Errorf("corrupt complete audit record at offset %d: %w", offset, err)
		}
		if event.ID != "" && previous.ID == event.ID {
			previous.Time = previous.Time.UTC()
			canonical, err := json.Marshal(previous)
			if err != nil || !bytes.Equal(canonical, data) {
				return fmt.Errorf("conflicting audit event ID %s", event.ID)
			}
			found = true
		}
		offset += int64(len(line))
	}
	if !found {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		data = append(data, '\n')
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
	}
	if err := a.syncFile(file); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(a.path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
