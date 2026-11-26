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

func TestRemoteAuditFailureRetainsCompletedKey(t *testing.T) {
	event := pqc.AuditEvent{ID: "receipt", Time: time.Now().UTC(), Operation: "key.rotate", KeyID: "key", KeyVersion: 2, Outcome: pqc.AuditSucceeded, Success: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "audit disk full", "audit_failure": event, "result": pqc.KeyMetadata{ID: "key", Version: 2}})
	}))
	defer server.Close()
	client := &remoteClient{baseURL: server.URL, client: server.Client()}
	result, err := client.Rotate(t.Context(), "key")
	var failure *pqc.AuditFailure
	if result == nil || result.Version != 2 || !errors.As(err, &failure) || failure.Event.ID != "receipt" || !errors.Is(err, pqc.ErrAuditPersistence) {
		t.Fatalf("remote receipt/result lost: %+v %v", result, err)
	}
}
