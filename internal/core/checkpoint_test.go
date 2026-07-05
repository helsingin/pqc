package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestAuditCheckpointDetectsTamperingAndVerifiesSignature(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "audit-signer", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}

	auditLog := strings.NewReader(`{"operation":"key.generate","key_id":"service-a","success":true}
{"operation":"sign","key_id":"signer-a","success":true}
`)
	checkpoint, err := BuildAuditCheckpoint(auditLog, now)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := SignAuditCheckpoint(ctx, manager, checkpoint, "audit-signer"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "audit-signer")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	validLog := bytes.NewBufferString(`{"operation":"key.generate","key_id":"service-a","success":true}
{"operation":"sign","key_id":"signer-a","success":true}
`)
	if err := VerifyAuditCheckpoint(validLog, checkpoint, publicKey); err != nil {
		t.Fatalf("verify valid checkpoint: %v", err)
	}

	tamperedLog := bytes.NewBufferString(`{"operation":"key.generate","key_id":"service-a","success":true}
{"operation":"decrypt","key_id":"service-a","success":true}
`)
	if err := VerifyAuditCheckpoint(tamperedLog, checkpoint, publicKey); err == nil {
		t.Fatalf("expected tampered audit log to fail verification")
	}
}

func TestTransparencyBundleVerifiesInventoryRoot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "org-root", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	service, err := manager.Generate(ctx, GenerateRequest{ID: "service-a", Algorithm: AlgorithmMLKEM768})
	if err != nil {
		t.Fatalf("generate service: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "org-root")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	report := BuildInventoryReport([]KeyMetadata{*service}, nil, now)
	checkpoint, err := BuildTransparencyCheckpoint(report, now)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := SignTransparencyCheckpoint(ctx, manager, checkpoint, "org-root"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	bundle, err := BuildTransparencyBundle(report, checkpoint)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := VerifyTransparencyBundle(bundle, publicKey); err != nil {
		t.Fatalf("verify bundle: %v", err)
	}

	bundle.Inventory.Keys[0].Version++
	if err := VerifyTransparencyBundle(bundle, publicKey); err == nil {
		t.Fatalf("expected modified inventory to fail verification")
	}
}

func TestTransparencyBundleIncludesRevocationManifest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "org-root", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	service, err := manager.Generate(ctx, GenerateRequest{ID: "service-a", Algorithm: AlgorithmMLKEM768})
	if err != nil {
		t.Fatalf("generate service: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "org-root")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	report := BuildInventoryReport([]KeyMetadata{*service}, nil, now)
	revocations := NewRevocationManifest(now)
	if _, err := revocations.Add("key", "service-a", "key-compromise", nil, now.Add(time.Minute)); err != nil {
		t.Fatalf("add revocation: %v", err)
	}
	checkpoint, err := BuildTransparencyCheckpointWithRevocations(report, &revocations, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if checkpoint.RevocationCount != 1 || checkpoint.RevocationRoot == "" || checkpoint.RevocationDigest == "" {
		t.Fatalf("checkpoint missing revocation state: %+v", checkpoint)
	}
	if err := SignTransparencyCheckpoint(ctx, manager, checkpoint, "org-root"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	bundle, err := BuildTransparencyBundleWithRevocations(report, &revocations, checkpoint)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := VerifyTransparencyBundle(bundle, publicKey); err != nil {
		t.Fatalf("verify bundle: %v", err)
	}

	tampered := bundle
	tampered.Revocations = &RevocationManifest{
		Schema:    bundle.Revocations.Schema,
		Hash:      bundle.Revocations.Hash,
		CreatedAt: bundle.Revocations.CreatedAt,
		Events:    append([]RevocationEvent(nil), bundle.Revocations.Events...),
	}
	tampered.Revocations.Events[0].Reason = "cessation-of-operation"
	if err := VerifyTransparencyBundle(tampered, publicKey); err == nil {
		t.Fatalf("expected tampered revocation manifest to fail verification")
	}

	withoutRevocations := bundle
	withoutRevocations.Revocations = nil
	if err := VerifyTransparencyBundle(withoutRevocations, publicKey); err == nil {
		t.Fatalf("expected missing revocation manifest to fail verification")
	}
}

type memoryStore struct {
	records map[string][]KeyRecord
}

func newMemoryStore() *memoryStore {
	return &memoryStore{records: make(map[string][]KeyRecord)}
}

func (s *memoryStore) Put(_ context.Context, record KeyRecord) error {
	s.records[record.ID] = append(s.records[record.ID], record)
	return nil
}

func (s *memoryStore) Get(_ context.Context, id string) (KeyRecord, error) {
	versions := s.records[id]
	if len(versions) == 0 {
		return KeyRecord{}, ErrKeyNotFound
	}
	return versions[len(versions)-1], nil
}

func (s *memoryStore) GetVersion(_ context.Context, id string, version int) (KeyRecord, error) {
	for _, record := range s.records[id] {
		if record.Version == version {
			return record, nil
		}
	}
	return KeyRecord{}, ErrKeyNotFound
}

func (s *memoryStore) List(_ context.Context) ([]KeyMetadata, error) {
	var out []KeyMetadata
	for _, versions := range s.records {
		if len(versions) == 0 {
			continue
		}
		out = append(out, metadataFromRecord(versions[len(versions)-1], true))
	}
	return out, nil
}
