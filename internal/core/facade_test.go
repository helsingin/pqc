package core_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pqc "github.com/helsingin/pqc"
	agefilestore "github.com/helsingin/pqc/store/agefile"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestEnvelopeRoundTripAndRotation(t *testing.T) {
	ctx := context.Background()
	manager := newTestManager(t)

	if _, err := manager.Generate(ctx, pqc.GenerateRequest{
		ID:        "service-a",
		Algorithm: pqc.AlgorithmMLKEM768,
	}); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	aad := []byte("tenant=demo")
	envelope, err := manager.Encrypt(ctx, "service-a", []byte("hello pqc"), pqc.EncryptOptions{AAD: aad})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plaintext, err := manager.Decrypt(ctx, envelope, pqc.EncryptOptions{AAD: aad})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "hello pqc" {
		t.Fatalf("plaintext = %q", plaintext)
	}

	if _, err := manager.Decrypt(ctx, envelope, pqc.EncryptOptions{AAD: []byte("wrong")}); err == nil {
		t.Fatalf("decrypt with wrong AAD succeeded")
	}

	if _, err := manager.Rotate(ctx, "service-a"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	plaintext, err = manager.Decrypt(ctx, envelope, pqc.EncryptOptions{AAD: aad})
	if err != nil {
		t.Fatalf("decrypt old envelope after rotation: %v", err)
	}
	if string(plaintext) != "hello pqc" {
		t.Fatalf("rotated plaintext = %q", plaintext)
	}
}

func TestSignatureRoundTripAndTamperFailure(t *testing.T) {
	ctx := context.Background()
	manager := newTestManager(t)

	if _, err := manager.Generate(ctx, pqc.GenerateRequest{
		ID:        "release-signer",
		Algorithm: pqc.AlgorithmMLDSA65,
	}); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := []byte("artifact digest")
	signature, err := manager.Sign(ctx, "release-signer", message, pqc.SignOptions{Context: []byte("release")})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := manager.Verify(ctx, message, signature); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := manager.Verify(ctx, []byte("tampered"), signature); !errors.Is(err, pqc.ErrInvalidSignature) {
		t.Fatalf("verify tampered error = %v, want ErrInvalidSignature", err)
	}

	if _, err := manager.Rotate(ctx, "release-signer"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := manager.Verify(ctx, message, signature); err != nil {
		t.Fatalf("verify previous signature after rotation: %v", err)
	}
}

func TestAlgorithmAliases(t *testing.T) {
	tests := map[string]pqc.Algorithm{
		"kyber768":    pqc.AlgorithmMLKEM768,
		"ml-kem-768":  pqc.AlgorithmMLKEM768,
		"dilithium3":  pqc.AlgorithmMLDSA65,
		"ml_dsa_65":   pqc.AlgorithmMLDSA65,
		"dilithium-5": pqc.AlgorithmMLDSA87,
		"ML-DSA-87":   pqc.AlgorithmMLDSA87,
	}
	for input, want := range tests {
		got, err := pqc.ParseAlgorithm(input)
		if err != nil {
			t.Fatalf("ParseAlgorithm(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseAlgorithm(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestFileStorePersistsKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := filestore.New(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	manager := pqc.NewManager(store)
	if _, err := manager.Generate(ctx, pqc.GenerateRequest{
		ID:        "persisted",
		Algorithm: pqc.AlgorithmMLKEM768,
	}); err != nil {
		t.Fatalf("generate: %v", err)
	}

	reopened, err := filestore.New(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	manager = pqc.NewManager(reopened)
	envelope, err := manager.Encrypt(ctx, "persisted", []byte("stored"), pqc.EncryptOptions{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plaintext, err := manager.Decrypt(ctx, envelope, pqc.EncryptOptions{})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("stored")) {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestAgeFileStoreEncryptsAndPersistsKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := agefilestore.New(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	manager := pqc.NewManager(store)
	if _, err := manager.Generate(ctx, pqc.GenerateRequest{
		ID:        "encrypted",
		Algorithm: pqc.AlgorithmMLKEM768,
	}); err != nil {
		t.Fatalf("generate: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read store dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("store files = %d, want 1", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read encrypted keyset: %v", err)
	}
	if bytes.Contains(data, []byte("private_key")) || bytes.Contains(data, []byte("public_key")) || bytes.Contains(data, []byte("encrypted")) {
		t.Fatalf("age store leaked plaintext keyset data: %q", data)
	}

	reopened, err := agefilestore.New(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	manager = pqc.NewManager(reopened)
	envelope, err := manager.Encrypt(ctx, "encrypted", []byte("stored encrypted"), pqc.EncryptOptions{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plaintext, err := manager.Decrypt(ctx, envelope, pqc.EncryptOptions{})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("stored encrypted")) {
		t.Fatalf("plaintext = %q", plaintext)
	}

	wrong, err := agefilestore.New(dir, "wrong passphrase")
	if err != nil {
		t.Fatalf("wrong store: %v", err)
	}
	if _, err := wrong.Get(ctx, "encrypted"); err == nil {
		t.Fatalf("wrong passphrase read succeeded")
	}
}

func TestFileAuditorRecordsMetadataOnlyEvents(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := filestore.New(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	auditor, err := pqc.NewFileAuditor(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("auditor: %v", err)
	}
	manager := pqc.NewManager(store, pqc.WithAuditor(auditor))

	if _, err := manager.Generate(ctx, pqc.GenerateRequest{
		ID:        "service-a",
		Algorithm: pqc.AlgorithmMLKEM768,
	}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := manager.Encrypt(ctx, "service-a", []byte("secret plaintext"), pqc.EncryptOptions{}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if bytes.Contains(data, []byte("secret plaintext")) {
		t.Fatalf("audit log contains plaintext: %s", data)
	}

	events := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2: %s", len(events), data)
	}
	var first pqc.AuditEvent
	if err := json.Unmarshal(events[0], &first); err != nil {
		t.Fatalf("unmarshal first event: %v", err)
	}
	if first.Operation != "key.generate" || first.KeyID != "service-a" || !first.Success {
		t.Fatalf("unexpected first event: %+v", first)
	}
}

func newTestManager(t *testing.T) *pqc.Manager {
	t.Helper()
	store, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return pqc.NewManager(store)
}
