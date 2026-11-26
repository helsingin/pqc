package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/helsingin/pqc"
	"github.com/helsingin/pqc/store/file"
)

func fixture(t *testing.T, algorithms ...pqc.Algorithm) (Statement, []pqc.SigningProvider, []pqc.PublicKey) {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	policy := Policy{Schema: PolicySchema, ID: "test-policy", Version: 1, Purpose: "archive", Context: "tenant-a", NotBefore: now.Unix() - 10, NotAfter: now.Unix() + 3600}
	var providers []pqc.SigningProvider
	var keys []pqc.PublicKey
	for _, algorithm := range algorithms {
		store, err := file.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		manager := pqc.NewManager(store)
		id := string(algorithm)
		if _, err := manager.Generate(t.Context(), pqc.GenerateRequest{ID: id, Algorithm: algorithm}); err != nil {
			t.Fatal(err)
		}
		key, err := manager.ExportPublic(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := KeyReference(*key)
		if err != nil {
			t.Fatal(err)
		}
		policy.Signers = append(policy.Signers, ref)
		providers = append(providers, manager)
		keys = append(keys, *key)
	}
	statement, err := NewStatement(policy, []byte("retained evidence"), "text/plain", now, []Field{{Key: "owner", Value: "example"}})
	if err != nil {
		t.Fatal(err)
	}
	return statement, providers, keys
}

func TestAllProfilesAndPolicyBoundSignatures(t *testing.T) {
	for _, algorithm := range []pqc.Algorithm{pqc.AlgorithmMLDSA65, pqc.AlgorithmMLDSA87, pqc.AlgorithmSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2256s} {
		t.Run(string(algorithm), func(t *testing.T) {
			statement, providers, keys := fixture(t, algorithm)
			document, err := Sign(t.Context(), statement, providers, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(document, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.ClaimedAt+1, 0)); err != nil {
				t.Fatal(err)
			}
			document.Statement.Metadata[0].Value = "forged"
			if err := Verify(document, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.ClaimedAt+1, 0)); err == nil {
				t.Fatal("metadata tampering accepted")
			}
		})
	}
}

func TestStrictPolicyRejectsStrippingAndDowngrade(t *testing.T) {
	statement, providers, keys := fixture(t, pqc.AlgorithmMLDSA65, pqc.AlgorithmSLHDSASHA2192s)
	signed, err := Sign(t.Context(), statement, providers, false)
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(statement.ClaimedAt+1, 0)
	if err := Verify(signed, []byte("retained evidence"), statement.Policy, keys, now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Envelope){
		"unsigned":  func(e *Envelope) { e.Signatures = nil },
		"stripped":  func(e *Envelope) { e.Signatures = e.Signatures[:1] },
		"duplicate": func(e *Envelope) { e.Signatures[1] = e.Signatures[0] },
		"reordered": func(e *Envelope) { e.Signatures[0], e.Signatures[1] = e.Signatures[1], e.Signatures[0] },
		"policy downgrade": func(e *Envelope) {
			e.Statement.Policy.Signers = e.Statement.Policy.Signers[:1]
			e.Signatures = e.Signatures[:1]
		},
		"purpose":      func(e *Envelope) { e.Statement.Policy.Purpose = "other" },
		"context":      func(e *Envelope) { e.Statement.Policy.Context = "tenant-b" },
		"schema":       func(e *Envelope) { e.Schema = "pqc.evidence.v99" },
		"claimed time": func(e *Envelope) { e.Statement.ClaimedAt-- },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var copy Envelope
			if err := json.Unmarshal(original, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err := Verify(&copy, []byte("retained evidence"), statement.Policy, keys, now); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
	if err := Verify(signed, []byte("changed"), statement.Policy, keys, now); err == nil {
		t.Fatal("payload accepted")
	}
	if err := Verify(signed, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.Policy.NotAfter, 0)); err == nil {
		t.Fatal("expired policy accepted")
	}
	if err := Verify(signed, []byte("retained evidence"), statement.Policy, keys, time.Time{}); err == nil {
		t.Fatal("missing clock accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if document, err := Sign(cancelled, statement, providers, false); err == nil || document != nil {
		t.Fatal("cancelled signing accepted")
	}
}
