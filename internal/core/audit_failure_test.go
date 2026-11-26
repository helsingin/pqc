package core

import (
	"context"
	"errors"
	"testing"
)

func TestAuditFailureRetainsCompletedResultWithoutRetry(t *testing.T) {
	failure := errors.New("disk full")
	store := newMemoryStore()
	calls := 0
	manager := NewManager(store, WithAuditor(AuditorFunc(func(context.Context, AuditEvent) error {
		calls++
		return failure
	})))
	key, err := manager.Generate(t.Context(), GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var auditErr *AuditFailure
	if !errors.As(err, &auditErr) || !errors.Is(err, failure) || !errors.Is(err, ErrAuditPersistence) || key == nil {
		t.Fatalf("completed result/audit error lost: %+v %v", key, err)
	}
	if auditErr.Event.Outcome != AuditSucceeded || !auditErr.Event.Success || auditErr.Event.ID == "" || calls != 1 {
		t.Fatalf("wrong outcome or implicit retry: %+v, calls=%d", auditErr.Event, calls)
	}
	saved, err := store.Get(t.Context(), "committed")
	if err != nil || saved.Version != 1 || len(store.records["committed"]) != 1 {
		t.Fatal("operation did not persist exactly once in this invocation")
	}
	_, err = manager.Generate(t.Context(), GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	if !errors.Is(err, ErrKeyExists) || !errors.Is(err, failure) || !errors.As(err, &auditErr) || auditErr.Event.Outcome != AuditFailed {
		t.Fatalf("operation and audit failures must both remain visible: %v", err)
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
	if result != nil || !errors.As(err, &uncertain) || !errors.Is(err, failure) || event.Outcome != AuditUnknown || event.Success || event.KeyVersion != 1 || uncertain.KeyVersion != 1 {
		t.Fatalf("misleading outcome: %+v %v", event, err)
	}
	if _, err := store.Get(t.Context(), "committed"); err != nil {
		t.Fatal("test write did not commit")
	}
}

func TestCancellationAfterCommitDoesNotRelabelOperation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	manager := NewManager(uncertainStore{Store: newMemoryStore(), afterPut: cancel}, WithAuditor(AuditorFunc(func(ctx context.Context, _ AuditEvent) error { return ctx.Err() })))
	result, err := manager.Generate(ctx, GenerateRequest{ID: "committed", Algorithm: AlgorithmMLDSA65})
	var failure *AuditFailure
	if result == nil || !errors.As(err, &failure) || !errors.Is(err, context.Canceled) || failure.Event.Outcome != AuditSucceeded {
		t.Fatalf("post-commit cancellation: %+v %v", result, err)
	}
}
