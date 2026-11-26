package core

import (
	"errors"
	"fmt"
)

type AuditOutcome string

const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditFailed    AuditOutcome = "failed"
	AuditUnknown   AuditOutcome = "unknown"
)

var ErrAuditPersistence = errors.New("audit persistence failed")

// UncertainOperationError means a store write returned an error after being
// attempted. The store may have committed it. Reconcile the named key version
// before retrying; this error is not evidence that the write did not occur.
type UncertainOperationError struct {
	Operation  string
	KeyID      string
	KeyVersion int
	Cause      error
}

func (e *UncertainOperationError) Error() string {
	return fmt.Sprintf("%s outcome unknown for key %s version %d; reconcile before retrying: %v", e.Operation, e.KeyID, e.KeyVersion, e.Cause)
}
func (e *UncertainOperationError) Unwrap() error { return e.Cause }

func auditOperationSucceeded(err error) bool {
	var failure *AuditFailure
	return errors.As(err, &failure) && failure.Event.Outcome == AuditSucceeded
}

// AuditFailure means auditing failed, independently of the operation outcome.
// A non-nil result may accompany this error when the operation succeeded.
// Do not repeat the operation automatically. The application owns reconciliation
// and audit handling; this library supplies no durable retry queue.
type AuditFailure struct {
	Event          AuditEvent
	Cause          error
	OperationError error
}

func (e *AuditFailure) Error() string {
	return fmt.Sprintf("%s: operation %s, event %s; retain any result and reconcile before retrying: %v", ErrAuditPersistence, e.Event.Outcome, e.Event.ID, e.Cause)
}
func (e *AuditFailure) Unwrap() []error {
	causes := []error{ErrAuditPersistence}
	if e.Cause != nil {
		causes = append(causes, e.Cause)
	}
	if e.OperationError != nil {
		causes = append(causes, e.OperationError)
	}
	return causes
}
