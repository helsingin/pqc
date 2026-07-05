package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMTCLogProofVerifiesSignedCheckpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "org-root", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "org-root")
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}
	fingerprint := PublicKeyFingerprint(publicKey.PublicKey)

	log := NewMTCLog(now)
	if _, err := log.Add("example.com", fingerprint, map[string]any{"role": "leaf"}, now); err != nil {
		t.Fatalf("add first entry: %v", err)
	}
	if _, err := log.Add("www.example.com", fingerprint, map[string]any{"role": "leaf"}, now.Add(time.Minute)); err != nil {
		t.Fatalf("add second entry: %v", err)
	}

	checkpoint, err := BuildMTCCheckpoint(log, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if checkpoint.TreeSize != 2 {
		t.Fatalf("tree size = %d, want 2", checkpoint.TreeSize)
	}
	if err := SignMTCCheckpoint(ctx, manager, checkpoint, "org-root"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	proof, err := BuildMTCProof(log, 1, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	if err := VerifyMTCProof(proof, checkpoint, publicKey); err != nil {
		t.Fatalf("verify proof: %v", err)
	}
}

func TestMTCLogProofRejectsTampering(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "org-root", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "org-root")
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}
	fingerprint := PublicKeyFingerprint(publicKey.PublicKey)

	log := NewMTCLog(now)
	for _, subject := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, err := log.Add(subject, fingerprint, nil, now); err != nil {
			t.Fatalf("add entry: %v", err)
		}
	}
	checkpoint, err := BuildMTCCheckpoint(log, now)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := SignMTCCheckpoint(ctx, manager, checkpoint, "org-root"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	proof, err := BuildMTCProof(log, 2, now)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	tamperedLeaf := *proof
	tamperedLeaf.Leaf.Subject = "evil.example.com"
	if err := VerifyMTCProof(&tamperedLeaf, checkpoint, publicKey); err == nil {
		t.Fatalf("expected tampered leaf to fail verification")
	}

	unsignedCheckpoint := *checkpoint
	unsignedCheckpoint.Signature = nil
	if err := VerifyMTCProof(proof, &unsignedCheckpoint, publicKey); err == nil {
		t.Fatalf("expected unsigned checkpoint to fail verification")
	}

	tamperedPath := *proof
	tamperedPath.Siblings = append([]MTCProofNode(nil), proof.Siblings...)
	tamperedPath.Siblings = append(tamperedPath.Siblings, MTCProofNode{
		Position: "right",
		Hash:     strings.Repeat("0", 64),
	})
	if err := VerifyMTCProof(&tamperedPath, checkpoint, publicKey); err == nil {
		t.Fatalf("expected malformed path to fail verification")
	}

	tamperedCheckpoint := *checkpoint
	tamperedCheckpoint.MerkleRoot = strings.Repeat("f", 64)
	if err := VerifyMTCProof(proof, &tamperedCheckpoint, publicKey); err == nil {
		t.Fatalf("expected tampered checkpoint to fail verification")
	}
}

func TestMTCLogRejectsMalformedEntries(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	if _, err := BuildMTCCheckpoint(MTCLog{}, now); err == nil {
		t.Fatalf("expected zero-value log to fail validation")
	}

	log := NewMTCLog(now)
	if _, err := log.Add("example.com", "not-a-fingerprint", nil, now); err == nil {
		t.Fatalf("expected malformed fingerprint to fail")
	}

	fingerprint := "sha256:" + strings.Repeat("a", 64)
	entry, err := log.Add("example.com", fingerprint, nil, now)
	if err != nil {
		t.Fatalf("add entry: %v", err)
	}
	log.Entries[entry.Index].PublicKeyFingerprint = "sha256:" + strings.Repeat("A", 64)
	if _, err := BuildMTCCheckpoint(log, now); err == nil {
		t.Fatalf("expected non-canonical fingerprint to fail validation")
	}
}
