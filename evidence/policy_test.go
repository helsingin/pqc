package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
)

func TestEveryStatementFieldIsAuthenticated(t *testing.T) {
	statement, providers, keys := fixture(t, pqc.AlgorithmMLDSA65)
	signed, err := Sign(t.Context(), statement, providers, false)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(signed)
	changes := map[string]func(*Statement){
		"policy identity": func(s *Statement) { s.Policy.ID += "other" },
		"policy version":  func(s *Statement) { s.Policy.Version++ },
		"start":           func(s *Statement) { s.Policy.NotBefore-- },
		"expiry":          func(s *Statement) { s.Policy.NotAfter++ },
		"key identity":    func(s *Statement) { s.Policy.Signers[0].KeyID += "other" },
		"key version":     func(s *Statement) { s.Policy.Signers[0].KeyVersion++ },
		"algorithm":       func(s *Statement) { s.Policy.Signers[0].Algorithm = pqc.AlgorithmMLDSA87 },
		"key digest":      func(s *Statement) { s.Policy.Signers[0].PublicKeyDigest = strings.Repeat("a", 128) },
		"payload digest":  func(s *Statement) { s.Payload.Digest = strings.Repeat("a", 128) },
		"payload length":  func(s *Statement) { s.Payload.Length++ },
		"payload hash":    func(s *Statement) { s.Payload.Hash = "SHA-256" },
		"media type":      func(s *Statement) { s.Payload.MediaType = "text/other" },
		"metadata key":    func(s *Statement) { s.Metadata[0].Key = "different" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var document Envelope
			_ = json.Unmarshal(wire, &document)
			change(&document.Statement)
			if err := Verify(&document, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.ClaimedAt+1, 0)); err == nil {
				t.Fatal("altered statement accepted")
			}
		})
	}
	wrongKeys := append([]pqc.PublicKey(nil), keys...)
	wrongKeys[0].PublicKey = append([]byte(nil), keys[0].PublicKey...)
	wrongKeys[0].PublicKey[0] ^= 1
	if err := Verify(signed, []byte("retained evidence"), statement.Policy, wrongKeys, time.Unix(statement.ClaimedAt+1, 0)); err == nil {
		t.Fatal("untrusted public material accepted")
	}
}

func TestLegacyArtifactRetainsCompletedSignatureOnAuditFailure(t *testing.T) {
	_, providers, keys := fixture(t, pqc.AlgorithmMLDSA65)
	calls := 0
	signer := auditFailureProvider{providers[0], "receipt", &calls}
	artifact := &profile.IssuedArtifact{Schema: profile.ArtifactSchema, Profile: "test", Type: "evidence", IssuedAt: time.Unix(1800000000, 0)}
	err := profile.SignArtifact(t.Context(), signer, keys[0].ID, artifact)
	if !errors.Is(err, pqc.ErrAuditPersistence) || artifact.Signature == nil {
		t.Fatalf("completed artifact signature lost: %v", err)
	}
	if err := profile.VerifyArtifactSignature(artifact, &keys[0]); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryNeedsFreshExplicitPolicySignatures(t *testing.T) {
	statement, providers, keys := fixture(t, pqc.AlgorithmMLDSA65, pqc.AlgorithmSLHDSASHA2192s)
	signed, err := Sign(t.Context(), statement, providers, false)
	if err != nil {
		t.Fatal(err)
	}
	recovery := statement.Policy
	recovery.ID = "authorized-recovery"
	recovery.Version = 2
	recovery.Signers = append([]SignerRef(nil), recovery.Signers[1:]...)
	recovery.NotBefore = statement.ClaimedAt + 100
	recovery.NotAfter = recovery.NotBefore + 600
	forged := *signed
	forged.Statement = statement
	forged.Statement.Policy = recovery
	forged.Statement.ClaimedAt = recovery.NotBefore
	forged.Signatures = []Signature{{Signer: 0, Value: signed.Signatures[1].Value}}
	now := time.Unix(recovery.NotBefore, 0)
	if err := Verify(&forged, []byte("retained evidence"), recovery, keys[1:], now); err == nil {
		t.Fatal("old signature transplanted into recovery policy")
	}
	fresh, err := NewStatement(recovery, []byte("retained evidence"), "text/plain", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	document, err := Sign(t.Context(), fresh, providers[1:], false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(document, []byte("retained evidence"), recovery, keys[1:], now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(document, []byte("retained evidence"), statement.Policy, keys, now); err == nil {
		t.Fatal("recovery accepted by normal policy")
	}
	if err := Verify(document, []byte("retained evidence"), recovery, keys[1:], now.Add(-time.Second)); err == nil {
		t.Fatal("premature recovery accepted")
	}
	if err := Verify(document, []byte("retained evidence"), recovery, keys[1:], time.Unix(recovery.NotAfter, 0)); err == nil {
		t.Fatal("expired recovery accepted")
	}
}

type badProvider struct {
	pqc.SigningProvider
	mode string
}

type auditFailureProvider struct {
	pqc.SigningProvider
	id    string
	calls *int
}

func (p auditFailureProvider) Sign(ctx context.Context, id string, message []byte, options pqc.SignOptions) (*pqc.SignatureEnvelope, error) {
	*p.calls++
	signature, err := p.SigningProvider.Sign(ctx, id, message, options)
	if err != nil {
		return nil, err
	}
	return signature, &pqc.AuditFailure{Event: pqc.AuditEvent{ID: p.id, Operation: "sign", KeyID: id, KeyVersion: signature.KeyVersion, Outcome: pqc.AuditSucceeded, Success: true}, Cause: errors.New("audit unavailable")}
}

func TestCompletedEvidenceRetainsEveryAuditReceipt(t *testing.T) {
	statement, providers, keys := fixture(t, pqc.AlgorithmMLDSA65, pqc.AlgorithmSLHDSASHA2192s)
	calls := 0
	for i := range providers {
		providers[i] = auditFailureProvider{providers[i], statement.Policy.Signers[i].KeyID, &calls}
	}
	document, err := Sign(t.Context(), statement, providers, false)
	var auditing *SigningAuditError
	if document == nil || !errors.As(err, &auditing) || !errors.Is(err, pqc.ErrAuditPersistence) || len(auditing.Receipts) != 2 {
		t.Fatalf("completed evidence/receipts lost: %v", err)
	}
	if err := Verify(document, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.ClaimedAt+1, 0)); err != nil {
		t.Fatal(err)
	}
	retried := map[string]bool{}
	for _, receipt := range auditing.Receipts {
		if err := pqc.RetryAudit(t.Context(), pqc.AuditorFunc(func(_ context.Context, event pqc.AuditEvent) error { retried[event.ID] = true; return nil }), receipt); err != nil {
			t.Fatal(err)
		}
	}
	if len(retried) != 2 || calls != 2 {
		t.Fatal("retry lost receipts or repeated signing")
	}
}

func (p badProvider) Sign(ctx context.Context, id string, message []byte, options pqc.SignOptions) (*pqc.SignatureEnvelope, error) {
	if p.mode == "failure" {
		return nil, errors.New("token unavailable")
	}
	signature, err := p.SigningProvider.Sign(ctx, id, message, options)
	if err != nil {
		return nil, err
	}
	switch p.mode {
	case "version":
		signature.KeyVersion++
	case "context":
		signature.Context = nil
	case "bytes":
		signature.Signature[0] ^= 1
	case "nil":
		return nil, nil
	}
	return signature, nil
}

func TestSigningRejectsProviderFailuresWithoutPartialEvidence(t *testing.T) {
	statement, providers, _ := fixture(t, pqc.AlgorithmMLDSA65)
	var missing *pqc.Manager
	if document, err := Sign(t.Context(), statement, []pqc.SigningProvider{missing}, false); err == nil || document != nil {
		t.Fatal("typed nil provider accepted")
	}
	for _, mode := range []string{"failure", "version", "context", "bytes", "nil"} {
		t.Run(mode, func(t *testing.T) {
			if document, err := Sign(t.Context(), statement, []pqc.SigningProvider{badProvider{providers[0], mode}}, false); err == nil || document != nil {
				t.Fatal("failed provider yielded accepted evidence")
			}
		})
	}
}
