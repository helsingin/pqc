package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditFailureRetainsCompletedResult(t *testing.T) {
	failure := errors.New("disk full")
	store := newMemoryStore()
	manager := NewManager(store, WithAuditor(AuditorFunc(func(context.Context, AuditEvent) error { return failure })))
	key, err := manager.Generate(t.Context(), GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var auditErr *AuditFailure
	if !errors.As(err, &auditErr) || !errors.Is(err, failure) || key == nil {
		t.Fatalf("completed result/audit error lost: %+v %v", key, err)
	}
	if auditErr.Event.Outcome != AuditSucceeded || !auditErr.Event.Success || auditErr.Event.ID == "" {
		t.Fatalf("wrong receipt: %+v", auditErr.Event)
	}
	saved, err := store.Get(t.Context(), "committed")
	if err != nil || saved.Version != 1 {
		t.Fatal("operation did not persist")
	}
	var retried AuditEvent
	if err := RetryAudit(t.Context(), AuditorFunc(func(_ context.Context, event AuditEvent) error { retried = event; return nil }), auditErr); err != nil {
		t.Fatal(err)
	}
	if retried.ID != auditErr.Event.ID || retried.Outcome != AuditSucceeded {
		t.Fatal("retry changed event")
	}
	if len(store.records["committed"]) != 1 {
		t.Fatal("retry repeated generation")
	}
}

type uncertainStore struct {
	Store
	afterPut func()
	failure  error
}

func (s uncertainStore) Put(ctx context.Context, record KeyRecord) error {
	if err := s.Store.Put(ctx, record); err != nil {
		return err
	}
	if s.afterPut != nil {
		s.afterPut()
	}
	return s.failure
}

func TestStoreCommitAcknowledgementFailureIsUnknown(t *testing.T) {
	store := newMemoryStore()
	failure := errors.New("acknowledgement lost")
	var event AuditEvent
	manager := NewManager(uncertainStore{Store: store, failure: failure}, WithAuditor(AuditorFunc(func(_ context.Context, e AuditEvent) error { event = e; return nil })))
	result, err := manager.Generate(t.Context(), GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var uncertain *UncertainOperationError
	if result != nil || !errors.As(err, &uncertain) || !errors.Is(err, failure) {
		t.Fatalf("unknown result: %+v %v", result, err)
	}
	if event.Outcome != AuditUnknown || event.Success || event.KeyVersion != 1 || uncertain.KeyVersion != 1 {
		t.Fatalf("misleading audit: %+v %v", event, err)
	}
	if _, err := store.Get(t.Context(), "committed"); err != nil {
		t.Fatal("test write did not commit")
	}
}

func TestCancellationAfterCommitDoesNotRelabelOperation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store := newMemoryStore()
	auditor, err := NewFileAuditor(filepath.Join(t.TempDir(), "events"))
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(uncertainStore{Store: store, afterPut: cancel}, WithAuditor(auditor))
	result, err := manager.Generate(ctx, GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var failure *AuditFailure
	if result == nil || !errors.As(err, &failure) || !errors.Is(err, context.Canceled) || failure.Event.Outcome != AuditSucceeded {
		t.Fatalf("post-commit cancellation: %+v %v", result, err)
	}
	if err := RetryAudit(t.Context(), auditor, failure); err != nil {
		t.Fatal(err)
	}
}

func TestDurableAuditRetriesAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	auditor, err := NewFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("sync failed after append")
	auditor.syncFile = func(*os.File) error { return failure }
	manager := NewManager(newMemoryStore(), WithAuditor(auditor))
	key, err := manager.Generate(t.Context(), GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var receipt *AuditFailure
	if key == nil || !errors.As(err, &receipt) || !errors.Is(err, failure) {
		t.Fatalf("sync failure lost: %v", err)
	}
	reopened, err := NewFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := RetryAudit(t.Context(), reopened, receipt); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte("\n")) != 1 {
		t.Fatal("retry duplicated event")
	}
	changed := receipt.Event
	changed.Operation = "forged"
	if err := reopened.Record(t.Context(), changed); err == nil {
		t.Fatal("conflicting ID accepted")
	}
	// An incomplete final append is recoverable without removing complete events.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"event_id":"interrupted`); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := RetryAudit(t.Context(), reopened, receipt); err != nil {
		t.Fatal(err)
	}
	repaired, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(repaired, data) {
		t.Fatalf("tail repair: %v", err)
	}
	file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{broken}\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := RetryAudit(t.Context(), reopened, receipt); err == nil {
		t.Fatal("corrupt complete record ignored")
	}
}

func TestLegacyAuditBytesArePreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	legacy := []byte("{\"operation\":\"sign\",\"success\":true}\n")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	auditor, err := NewFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{ID: "new", Time: time.Unix(1800000000, 0).UTC(), Operation: "sign", Outcome: AuditSucceeded, Success: true}
	if err := auditor.Record(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, legacy) {
		t.Fatal("legacy bytes changed")
	}
	var decoded AuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(data[len(legacy):]), &decoded); err != nil || decoded.ID != event.ID {
		t.Fatalf("new record: %+v %v", decoded, err)
	}
}
