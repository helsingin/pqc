package mtc

import (
	"context"
	"encoding/json"
	"testing"

	pqc "github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestEstimateUsesDraft04AndTreeSize(t *testing.T) {
	plugin := New()
	result, err := plugin.Estimate(context.Background(), profile.EstimateRequest{
		Inputs: json.RawMessage(`{"certificate_type":"landmark","tree_size":4400000}`),
	})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if result.Profile != ID {
		t.Fatalf("profile = %q", result.Profile)
	}
	found := false
	for _, estimate := range result.Estimates {
		if estimate.Metric == "tls_auth_overhead_landmark" {
			found = true
			if estimate.Value != 736 {
				t.Fatalf("tls_auth_overhead_landmark = %d", estimate.Value)
			}
			if estimate.Evidence["supported_draft"] != SupportedDraft {
				t.Fatalf("supported draft evidence = %#v", estimate.Evidence["supported_draft"])
			}
		}
	}
	if !found {
		t.Fatalf("missing tls_auth_overhead_landmark estimate: %#v", result.Estimates)
	}
}

func TestIssueRejectsUnsupportedDraftVersion(t *testing.T) {
	plugin := New()
	_, err := plugin.Issue(context.Background(), profile.IssueRequest{
		ProfileVersion: "draft-ietf-plants-merkle-tree-certs-03",
	})
	if err == nil {
		t.Fatalf("expected unsupported draft error")
	}
}

func TestEstimateSingleLeafTreeHasNoInclusionProofHashes(t *testing.T) {
	plugin := New()
	result, err := plugin.Estimate(context.Background(), profile.EstimateRequest{
		Inputs: json.RawMessage(`{"tree_size":1}`),
	})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	for _, estimate := range result.Estimates {
		if estimate.Metric == "landmark_inclusion_proof" {
			if estimate.Value != 0 {
				t.Fatalf("single-leaf proof bytes = %d", estimate.Value)
			}
			if estimate.Evidence["proof_hashes"] != 0 {
				t.Fatalf("single-leaf proof hashes = %#v", estimate.Evidence["proof_hashes"])
			}
			return
		}
	}
	t.Fatalf("missing landmark_inclusion_proof estimate: %#v", result.Estimates)
}

func TestNormalizeInputsDefaultsDraft04Fields(t *testing.T) {
	normalized, err := normalizeInputs(json.RawMessage(`{"tree_size":44}`))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var input Input
	if err := json.Unmarshal(normalized, &input); err != nil {
		t.Fatalf("unmarshal normalized: %v", err)
	}
	if input.CertificateType != landmarkCertificate {
		t.Fatalf("certificate type = %q", input.CertificateType)
	}
	if input.HashAlgorithm != defaultHashAlgorithm {
		t.Fatalf("hash algorithm = %q", input.HashAlgorithm)
	}
}

func TestVerifyRejectsWrongArtifactType(t *testing.T) {
	plugin := New()
	artifact, publicKey := signedArtifactWithType(t, plugin, "wrong-mtc-artifact")
	result, err := plugin.Verify(context.Background(), profile.VerifyRequest{
		Artifact:  artifact,
		PublicKey: publicKey,
	})
	if err == nil {
		t.Fatalf("expected artifact type verification error")
	}
	if result == nil || result.OK {
		t.Fatalf("verify result = %#v", result)
	}
	found := false
	for _, finding := range result.Findings {
		if finding.Subject == "artifact_type" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing artifact_type finding: %#v", result.Findings)
	}
}

func signedArtifactWithType(t *testing.T, plugin *Plugin, artifactType string) (*profile.IssuedArtifact, *pqc.PublicKey) {
	t.Helper()
	ctx := context.Background()
	store, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	manager := pqc.NewManager(store)
	if _, err := manager.Generate(ctx, pqc.GenerateRequest{ID: "signer", Algorithm: pqc.AlgorithmMLDSA65}); err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	artifact, err := plugin.Issue(ctx, profile.IssueRequest{
		Subject: profile.Subject{
			CommonName: "example.com",
		},
		SignKey: "signer",
		Signer:  manager,
	})
	if err != nil {
		t.Fatalf("issue artifact: %v", err)
	}
	artifact.Type = artifactType
	artifact.Signature = nil
	if err := profile.SignArtifact(ctx, manager, "signer", artifact); err != nil {
		t.Fatalf("sign wrong-type artifact: %v", err)
	}
	publicKey, err := manager.ExportPublic(ctx, "signer")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return artifact, publicKey
}
