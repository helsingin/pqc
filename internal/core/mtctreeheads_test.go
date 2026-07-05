package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMTCTreeheadCacheVerifiesSignedCheckpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	checkpoint, publicKey := signedMTCTestCheckpoint(t, ctx, now, "example.com")

	entry, err := NewMTCTreeheadEntry("https://mtc.example.test/treeheads", "test-log", *checkpoint, *publicKey, now)
	if err != nil {
		t.Fatalf("treehead entry: %v", err)
	}
	cache := NewMTCTreeheadCache("https://mtc.example.test/treeheads", []MTCTreeheadEntry{entry}, now)

	result, err := VerifyMTCTreeheadCache(cache)
	if err != nil {
		t.Fatalf("verify cache: %v", err)
	}
	if !result.OK || result.Verified != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestMTCTreeheadCacheDetectsConflictingRoots(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	firstCheckpoint, firstPublicKey := signedMTCTestCheckpoint(t, ctx, now, "a.example.com")
	secondCheckpoint, secondPublicKey := signedMTCTestCheckpoint(t, ctx, now.Add(time.Minute), "b.example.com")

	firstEntry, err := NewMTCTreeheadEntry("https://mtc.example.test/treeheads", "test-log", *firstCheckpoint, *firstPublicKey, now)
	if err != nil {
		t.Fatalf("first treehead entry: %v", err)
	}
	secondEntry, err := NewMTCTreeheadEntry("https://mtc.example.test/treeheads", "test-log", *secondCheckpoint, *secondPublicKey, now)
	if err != nil {
		t.Fatalf("second treehead entry: %v", err)
	}
	cache := NewMTCTreeheadCache("https://mtc.example.test/treeheads", []MTCTreeheadEntry{firstEntry, secondEntry}, now)

	result, err := VerifyMTCTreeheadCache(cache)
	if err == nil {
		t.Fatalf("expected conflicting roots to fail")
	}
	if result == nil || result.OK {
		t.Fatalf("result = %+v", result)
	}
}

func TestParseMTCTreeheadSourceSupportsCacheAndCheckpointDocuments(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	checkpoint, publicKey := signedMTCTestCheckpoint(t, ctx, now, "example.com")
	checkpointJSON, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}

	cache, err := ParseMTCTreeheadSource(checkpointJSON, "https://mtc.example.test/checkpoint.json", publicKey, "test-log", now)
	if err != nil {
		t.Fatalf("parse checkpoint source: %v", err)
	}
	if len(cache.Treeheads) != 1 {
		t.Fatalf("treeheads = %d, want 1", len(cache.Treeheads))
	}
	if _, err := ParseMTCTreeheadSource(checkpointJSON, "https://mtc.example.test/checkpoint.json", nil, "test-log", now); err == nil {
		t.Fatalf("expected checkpoint source without public key to fail")
	}

	cacheJSON, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	parsed, err := ParseMTCTreeheadSource(cacheJSON, "https://mtc.example.test/treeheads.json", nil, "", now)
	if err != nil {
		t.Fatalf("parse cache source: %v", err)
	}
	if parsed.Treeheads[0].ID != cache.Treeheads[0].ID {
		t.Fatalf("parsed treehead id = %q, want %q", parsed.Treeheads[0].ID, cache.Treeheads[0].ID)
	}
}

func signedMTCTestCheckpoint(t *testing.T, ctx context.Context, now time.Time, subject string) (*MTCCheckpoint, *PublicKey) {
	t.Helper()
	manager := NewManager(newMemoryStore(), WithClock(func() time.Time { return now }))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "org-root", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "org-root")
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}
	log := NewMTCLog(now)
	if _, err := log.Add(subject, PublicKeyFingerprint(publicKey.PublicKey), nil, now); err != nil {
		t.Fatalf("add entry: %v", err)
	}
	checkpoint, err := BuildMTCCheckpoint(log, now)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := SignMTCCheckpoint(ctx, manager, checkpoint, "org-root"); err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	return checkpoint, publicKey
}
