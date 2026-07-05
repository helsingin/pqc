package core

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRevocationManifestCanonicalizesAndRejectsDuplicates(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manifest := NewRevocationManifest(now)

	keyEvent, err := manifest.Add("key", "service-a", "Key_Compromise", nil, now)
	if err != nil {
		t.Fatalf("add key revocation: %v", err)
	}
	if keyEvent.Reason != "key-compromise" {
		t.Fatalf("reason = %q", keyEvent.Reason)
	}

	metadata := map[string]any{
		"nested": map[string]any{"value": "before"},
	}
	leafEvent, err := manifest.Add("mtc-leaf", "001", "key-compromise", metadata, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("add MTC leaf revocation: %v", err)
	}
	if leafEvent.Subject != "1" {
		t.Fatalf("leaf subject = %q", leafEvent.Subject)
	}
	metadata["nested"].(map[string]any)["value"] = "after"
	nested := manifest.Events[1].Metadata["nested"].(map[string]any)
	if nested["value"] != "before" {
		t.Fatalf("manifest metadata was mutated through caller alias: %+v", nested)
	}
	if _, err := manifest.Add("mtc-leaf", "1", "key-compromise", nil, now.Add(2*time.Minute)); err == nil {
		t.Fatalf("expected duplicate MTC leaf revocation to fail")
	}

	var encoded bytes.Buffer
	if err := WriteRevocationManifest(&encoded, manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	roundTripped, err := ReadRevocationManifest(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := ValidateRevocationManifest(roundTripped); err != nil {
		t.Fatalf("validate round trip: %v", err)
	}

	tampered := roundTripped
	tampered.Events[1].Subject = "001"
	if err := ValidateRevocationManifest(tampered); err == nil {
		t.Fatalf("expected non-canonical MTC leaf subject to fail validation")
	}
}

func TestReadRevocationManifestRejectsDuplicateSubjects(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manifest := NewRevocationManifest(now)
	first, err := manifest.Add("key", "service-a", "key-compromise", nil, now)
	if err != nil {
		t.Fatalf("add first event: %v", err)
	}
	second := RevocationEvent{
		Type:      "key",
		Subject:   "service-a",
		Reason:    "cessation-of-operation",
		RevokedAt: now.Add(time.Minute),
	}
	second.ID, err = RevocationEventID(second)
	if err != nil {
		t.Fatalf("second event id: %v", err)
	}
	firstData, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first event: %v", err)
	}
	secondData, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second event: %v", err)
	}
	jsonl := bytes.NewBuffer(nil)
	jsonl.Write(firstData)
	jsonl.WriteByte('\n')
	jsonl.Write(secondData)
	jsonl.WriteByte('\n')
	if _, err := ReadRevocationManifest(jsonl); err == nil {
		t.Fatalf("expected duplicate revocation subject to fail")
	}
}
