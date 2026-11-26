package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/helsingin/pqc"
)

func TestAuditFailureHTTPRetainsOutcomeAndResult(t *testing.T) {
	for _, outcome := range []pqc.AuditOutcome{pqc.AuditSucceeded, pqc.AuditFailed, pqc.AuditUnknown} {
		t.Run(string(outcome), func(t *testing.T) {
			event := pqc.AuditEvent{ID: "receipt", Time: time.Now().UTC(), Operation: "key.rotate", KeyID: "key", KeyVersion: 2, Outcome: outcome, Success: outcome == pqc.AuditSucceeded}
			failure := &pqc.AuditFailure{Event: event, Cause: errors.New("disk full"), OperationError: pqc.ErrKeyNotFound}
			response := httptest.NewRecorder()
			writeResult(response, &pqc.KeyMetadata{ID: "key", Version: 2}, failure)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status %d", response.Code)
			}
			var body struct {
				Error  string           `json:"error"`
				Audit  pqc.AuditEvent   `json:"audit_failure"`
				Result *pqc.KeyMetadata `json:"result"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Audit.ID != event.ID || body.Audit.Outcome != outcome || body.Error == "" {
				t.Fatalf("receipt lost: %+v", body)
			}
			if outcome == pqc.AuditSucceeded {
				if body.Result == nil || body.Result.Version != 2 {
					t.Fatal("completed result lost")
				}
			} else if body.Result != nil {
				t.Fatal("failed/unknown operation exposed a completed result")
			}
			if statusForError(failure) != http.StatusInternalServerError {
				t.Fatal("audit failure misclassified as key error")
			}
		})
	}
}
