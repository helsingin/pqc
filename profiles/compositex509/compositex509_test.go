package compositex509

import (
	"context"
	"encoding/json"
	"testing"

	pqc "github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestEstimateUsesDraftSnapshotAndRecommendedDefault(t *testing.T) {
	plugin := New()
	result, err := plugin.Estimate(context.Background(), profile.EstimateRequest{})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if result.Profile != ID {
		t.Fatalf("profile = %q", result.Profile)
	}
	found := false
	for _, estimate := range result.Estimates {
		if estimate.Metric == "tls_auth_overhead" {
			found = true
			if estimate.Value != 20939 {
				t.Fatalf("tls_auth_overhead = %d", estimate.Value)
			}
			if estimate.Evidence["composite_algorithm"] != defaultCompositeAlgorithm {
				t.Fatalf("algorithm evidence = %#v", estimate.Evidence["composite_algorithm"])
			}
			if estimate.Evidence["supported_version"] != SupportedVersion {
				t.Fatalf("supported version evidence = %#v", estimate.Evidence["supported_version"])
			}
			if estimate.Evidence["protocol_compatible"] != true {
				t.Fatalf("protocol compatibility evidence = %#v", estimate.Evidence["protocol_compatible"])
			}
		}
	}
	if !found {
		t.Fatalf("missing tls_auth_overhead estimate: %#v", result.Estimates)
	}
}

func TestEstimateUsesSelectedCompositeAlgorithm(t *testing.T) {
	plugin := New()
	result, err := plugin.Estimate(context.Background(), profile.EstimateRequest{
		Inputs: json.RawMessage(`{"composite_algorithm":"id-MLDSA44-RSA2048-PSS-SHA256","chain_signature_count":5,"chain_public_key_count":2}`),
	})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	for _, estimate := range result.Estimates {
		if estimate.Metric == "tls_auth_overhead" && estimate.Value != 16544 {
			t.Fatalf("tls_auth_overhead = %d", estimate.Value)
		}
	}
}

func TestNormalizeInputsDefaultsCompositeFields(t *testing.T) {
	normalized, err := normalizeInputs(json.RawMessage(`{"subject":"example.com"}`))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var input Input
	if err := json.Unmarshal(normalized, &input); err != nil {
		t.Fatalf("unmarshal normalized: %v", err)
	}
	if input.CompositeAlgorithm != defaultCompositeAlgorithm {
		t.Fatalf("composite algorithm = %q", input.CompositeAlgorithm)
	}
	if input.CertificateRole != defaultCertificateRole {
		t.Fatalf("certificate role = %q", input.CertificateRole)
	}
	if input.ChainSignatureCount != defaultChainSignatures {
		t.Fatalf("chain signature count = %d", input.ChainSignatureCount)
	}
	if len(algorithms) != 18 {
		t.Fatalf("supported algorithm count = %d", len(algorithms))
	}
}

func TestIssueRejectsUnsupportedDraftSnapshot(t *testing.T) {
	plugin := New()
	_, err := plugin.Issue(context.Background(), profile.IssueRequest{
		ProfileVersion: "draft-ietf-lamps-pq-composite-sigs-14",
	})
	if err == nil {
		t.Fatalf("expected unsupported draft error")
	}
}

func TestVerifyRejectsWrongArtifactType(t *testing.T) {
	plugin := New()
	artifact, publicKey := signedArtifactWithType(t, plugin, "wrong-composite-x509-artifact")
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
