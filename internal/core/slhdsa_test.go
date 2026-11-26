package core_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	pqc "github.com/helsingin/pqc"
	"github.com/helsingin/pqc/store/agefile"
	filestore "github.com/helsingin/pqc/store/file"
)

var slhAlgorithms = []pqc.Algorithm{pqc.AlgorithmSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2256s}

func TestSLHDSAKnownAnswers(t *testing.T) {
	// Published ACVP test keys, not operational keys. Compare the complete
	// deterministic/randomized output to the digest of the expected signature.
	var vectors []struct {
		Algorithm                                                 pqc.Algorithm
		TCID                                                      int
		PrivateKey, Message, Context, Randomness, SignatureSHA256 string
		Randomized                                                bool
	}
	data, err := os.ReadFile("testdata/slhdsa-acvp.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(string(v.Algorithm)+"/"+v.SignatureSHA256[:8], func(t *testing.T) {
			store, err := filestore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			private := decode(v.PrivateKey)
			record := pqc.KeyRecord{ID: "acvp", Version: 1, Algorithm: v.Algorithm, Use: pqc.KeyUseSignature, PrivateKey: private, PublicKey: private[len(private)/2:], CreatedAt: time.Now().UTC()}
			if err := store.Put(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			manager := pqc.NewManager(store, pqc.WithRand(bytes.NewReader(decode(v.Randomness))))
			message := decode(v.Message)
			sig, err := manager.Sign(t.Context(), record.ID, message, pqc.SignOptions{Context: decode(v.Context), Randomized: v.Randomized})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(sig.Signature)
			if hex.EncodeToString(digest[:]) != v.SignatureSHA256 {
				t.Fatalf("ACVP tcId %d signature mismatch", v.TCID)
			}
			if err := manager.Verify(t.Context(), message, sig); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSLHDSAPersistenceRotationAndRejection(t *testing.T) {
	for _, algorithm := range slhAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			store, err := filestore.New(dir)
			if err != nil {
				t.Fatal(err)
			}
			manager := pqc.NewManager(store)
			if _, err := manager.Generate(ctx, pqc.GenerateRequest{ID: "signer", Algorithm: algorithm}); err != nil {
				t.Fatal(err)
			}
			public, err := manager.ExportPublic(ctx, "signer")
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("migration evidence")
			context := bytes.Repeat([]byte{0x42}, 255)
			sig, err := manager.Sign(ctx, "signer", message, pqc.SignOptions{Context: context})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(sig)
			if err != nil {
				t.Fatal(err)
			}
			var saved pqc.SignatureEnvelope
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			reopened, err := filestore.New(dir)
			if err != nil {
				t.Fatal(err)
			}
			manager = pqc.NewManager(reopened)
			if err := manager.Verify(ctx, message, &saved); err != nil {
				t.Fatal(err)
			}
			if err := pqc.VerifyWithPublicKey(*public, message, &saved); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Rotate(ctx, "signer"); err != nil {
				t.Fatal(err)
			}
			if err := manager.Verify(ctx, message, &saved); err != nil {
				t.Fatalf("historical verification: %v", err)
			}
			rotated, err := manager.ExportPublic(ctx, "signer")
			if err != nil {
				t.Fatal(err)
			}
			if rotated.Algorithm != algorithm || rotated.Version != 2 {
				t.Fatal("rotation changed algorithm or lost version")
			}
			if err := pqc.VerifyWithPublicKey(*rotated, message, &saved); err == nil {
				t.Fatal("accepted wrong key version")
			}
			// Same identity/version metadata but different material must also fail.
			wrong := *rotated
			wrong.Version = public.Version
			if err := pqc.VerifyWithPublicKey(wrong, message, &saved); err == nil {
				t.Fatal("accepted wrong public key")
			}
			mutations := map[string]func(*pqc.SignatureEnvelope){
				"context":               func(s *pqc.SignatureEnvelope) { s.Context = []byte("wrong") },
				"overlong-context":      func(s *pqc.SignatureEnvelope) { s.Context = make([]byte, 256) },
				"empty-signature":       func(s *pqc.SignatureEnvelope) { s.Signature = nil },
				"truncated":             func(s *pqc.SignatureEnvelope) { s.Signature = s.Signature[:len(s.Signature)-1] },
				"trailing-data":         func(s *pqc.SignatureEnvelope) { s.Signature = append(s.Signature, 0) },
				"tampered":              func(s *pqc.SignatureEnvelope) { s.Signature[len(s.Signature)/2] ^= 1 },
				"wrong-algorithm":       func(s *pqc.SignatureEnvelope) { s.Algorithm = pqc.AlgorithmMLDSA65 },
				"unsupported-algorithm": func(s *pqc.SignatureEnvelope) { s.Algorithm = "SLH-DSA-SHA2-128s" },
				"wrong-schema":          func(s *pqc.SignatureEnvelope) { s.Schema = "pqc.signature.v2" },
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					copySig := saved
					copySig.Signature = bytes.Clone(saved.Signature)
					copySig.Context = bytes.Clone(saved.Context)
					mutate(&copySig)
					if err := pqc.VerifyWithPublicKey(*public, message, &copySig); !errors.Is(err, pqc.ErrInvalidSignature) {
						t.Fatalf("got %v, want ErrInvalidSignature", err)
					}
				})
			}
			for _, n := range []int{0, len(public.PublicKey) - 1, len(public.PublicKey) + 1} {
				bad := *public
				bad.PublicKey = make([]byte, n)
				if err := pqc.VerifyWithPublicKey(bad, message, &saved); !errors.Is(err, pqc.ErrInvalidSignature) {
					t.Fatalf("accepted malformed public key length %d: %v", n, err)
				}
			}
			if err := manager.Verify(ctx, []byte("altered"), &saved); !errors.Is(err, pqc.ErrInvalidSignature) {
				t.Fatalf("altered message: %v", err)
			}
			if _, err := manager.Sign(ctx, "signer", message, pqc.SignOptions{Context: make([]byte, 256)}); err == nil {
				t.Fatal("accepted overlong signing context")
			}
			// Empty messages and nil contexts remain valid in pure mode.
			empty, err := manager.Sign(ctx, "signer", nil, pqc.SignOptions{Randomized: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Verify(ctx, nil, empty); err != nil {
				t.Fatal(err)
			}
			failedRandom := pqc.NewManager(reopened, pqc.WithRand(bytes.NewReader(nil)))
			if _, err := failedRandom.Sign(ctx, "signer", message, pqc.SignOptions{Randomized: true}); !errors.Is(err, io.EOF) {
				t.Fatalf("failed randomness: %v", err)
			}
			if _, err := failedRandom.Generate(ctx, pqc.GenerateRequest{ID: "no-entropy", Algorithm: algorithm}); err == nil {
				t.Fatal("generated without entropy")
			}
			if _, err := manager.Get(ctx, "no-entropy"); !errors.Is(err, pqc.ErrKeyNotFound) {
				t.Fatal("persisted failed generation")
			}
			// Persisted keys keep their signature-only use.
			keys, err := manager.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 1 || keys[0].Use != pqc.KeyUseSignature {
				t.Fatal("incorrect key inventory")
			}
		})
	}
}

func TestSLHDSAAgeStore(t *testing.T) {
	for _, algorithm := range slhAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			dir := t.TempDir()
			store, err := agefile.New(dir, "test passphrase")
			if err != nil {
				t.Fatal(err)
			}
			manager := pqc.NewManager(store)
			if _, err := manager.Generate(t.Context(), pqc.GenerateRequest{ID: "signer", Algorithm: algorithm}); err != nil {
				t.Fatal(err)
			}
			// Re-open before signing, exercising decryption and algorithm decoding.
			reopened, err := agefile.New(dir, "test passphrase")
			if err != nil {
				t.Fatal(err)
			}
			manager = pqc.NewManager(reopened)
			message := []byte("encrypted-store artifact")
			sig, err := manager.Sign(t.Context(), "signer", message, pqc.SignOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Verify(t.Context(), message, sig); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSLHDSAParameterSelection(t *testing.T) {
	for _, a := range slhAlgorithms {
		for _, input := range []string{string(a), strings.ToLower(string(a)), strings.ReplaceAll(string(a), "-", "_")} {
			got, err := pqc.ParseAlgorithm(input)
			if err != nil || got != a {
				t.Fatalf("ParseAlgorithm(%q) = %s, %v", input, got, err)
			}
		}
	}
	for _, input := range []string{"slh-dsa", "sphincs+", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-256s"} {
		if _, err := pqc.ParseAlgorithm(input); err == nil {
			t.Fatalf("accepted unsupported/ambiguous algorithm %q", input)
		}
	}
}
