package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCheckpointSignaturesSurviveAuditFailure(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	manager := NewManager(newMemoryStore(), WithAuditor(AuditorFunc(func(_ context.Context, event AuditEvent) error {
		if event.Operation == "sign" {
			return errors.New("audit offline")
		}
		return nil
	})))
	if _, err := manager.Generate(ctx, GenerateRequest{ID: "signer", Algorithm: AlgorithmMLDSA65}); err != nil {
		t.Fatal(err)
	}
	public, err := manager.ExportPublic(ctx, "signer")
	if err != nil {
		t.Fatal(err)
	}
	check := func(err error, signature *SignatureEnvelope) {
		t.Helper()
		if !errors.Is(err, ErrAuditPersistence) || signature == nil {
			t.Fatalf("completed signature lost: %v", err)
		}
	}
	const log = "{\"operation\":\"test\"}\n"
	audit, err := BuildAuditCheckpoint(strings.NewReader(log), now)
	if err != nil {
		t.Fatal(err)
	}
	err = SignAuditCheckpoint(ctx, manager, audit, "signer")
	check(err, audit.Signature)
	if err := VerifyAuditCheckpoint(strings.NewReader(log), audit, public); err != nil {
		t.Fatal(err)
	}
	inventory := BuildInventoryReport(nil, nil, now)
	transparency, err := BuildTransparencyCheckpoint(inventory, now)
	if err != nil {
		t.Fatal(err)
	}
	err = SignTransparencyCheckpoint(ctx, manager, transparency, "signer")
	check(err, transparency.Signature)
	if err := VerifyTransparencyCheckpoint(inventory, transparency, public); err != nil {
		t.Fatal(err)
	}
	tree := NewMTCLog(now)
	if _, err := tree.Add("example.invalid", PublicKeyFingerprint(public.PublicKey), nil, now); err != nil {
		t.Fatal(err)
	}
	mtc, err := BuildMTCCheckpoint(tree, now)
	if err != nil {
		t.Fatal(err)
	}
	err = SignMTCCheckpoint(ctx, manager, mtc, "signer")
	check(err, mtc.Signature)
	proof, err := BuildMTCProof(tree, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMTCProof(proof, mtc, public); err != nil {
		t.Fatal(err)
	}
}
