package fndsa

import (
	"context"
	"encoding/json"
	"testing"

	pqc "github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestEstimateUsesDraftAndDefaultFNDSA512(t *testing.T) {
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
			if estimate.Value != 5124 {
				t.Fatalf("tls_auth_overhead = %d", estimate.Value)
			}
			if estimate.Evidence["parameter_set"] != defaultParameterSet {
				t.Fatalf("parameter set evidence = %#v", estimate.Evidence["parameter_set"])
			}
			if estimate.Evidence["supported_version"] != SupportedVersion {
				t.Fatalf("supported version evidence = %#v", estimate.Evidence["supported_version"])
			}
			if estimate.Evidence["x509_oid_status"] != x509OIDAssignmentStatus {
				t.Fatalf("oid status evidence = %#v", estimate.Evidence["x509_oid_status"])
			}
			if estimate.Evidence["web_tls_viable"] != false {
				t.Fatalf("web tls viability evidence = %#v", estimate.Evidence["web_tls_viable"])
			}
		}
	}
	if !found {
		t.Fatalf("missing tls_auth_overhead estimate: %#v", result.Estimates)
	}
}

func TestEstimateUsesFNDSA1024(t *testing.T) {
	plugin := New()
	result, err := plugin.Estimate(context.Background(), profile.EstimateRequest{
		Inputs: json.RawMessage(`{"parameter_set":"fn-dsa-1024","chain_signature_count":5,"chain_public_key_count":2}`),
	})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	for _, estimate := range result.Estimates {
		if estimate.Metric == "tls_auth_overhead" && estimate.Value != 9986 {
			t.Fatalf("tls_auth_overhead = %d", estimate.Value)
		}
	}
}

func TestNormalizeInputsDefaultsFNDSAFields(t *testing.T) {
	normalized, err := normalizeInputs(json.RawMessage(`{"subject":"example.com","key_usage":["keyCertSign","cRLSign"]}`))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var input Input
	if err := json.Unmarshal(normalized, &input); err != nil {
		t.Fatalf("unmarshal normalized: %v", err)
	}
	if input.ParameterSet != defaultParameterSet {
		t.Fatalf("parameter set = %q", input.ParameterSet)
	}
	if input.CertificateRole != defaultCertificateRole {
		t.Fatalf("certificate role = %q", input.CertificateRole)
	}
	if input.ChainSignatureCount != defaultChainSignatures {
		t.Fatalf("chain signature count = %d", input.ChainSignatureCount)
	}
}

func TestNormalizeInputsRejectsHashFNDSA(t *testing.T) {
	_, err := normalizeInputs(json.RawMessage(`{"pre_hash":true}`))
	if err == nil {
		t.Fatalf("expected pre-hash rejection")
	}
}

func TestNormalizeInputsRejectsNonEmptyContextString(t *testing.T) {
	_, err := normalizeInputs(json.RawMessage(`{"context_string":"ca-profile"}`))
	if err == nil {
		t.Fatalf("expected non-empty context string rejection")
	}
}

func TestInspectWarnsWhenCAUsesFNDSA512(t *testing.T) {
	plugin := New()
	result, err := plugin.Inspect(context.Background(), profile.InspectRequest{
		Inputs: json.RawMessage(`{"parameter_set":"fn-dsa-512","certificate_role":"intermediate"}`),
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.Subject == "security_category" {
			if finding.Evidence["recommended_parameter"] != "fn-dsa-1024" {
				t.Fatalf("recommended parameter = %#v", finding.Evidence["recommended_parameter"])
			}
			return
		}
	}
	t.Fatalf("missing security_category warning: %#v", result.Findings)
}

func TestIssueRejectsUnsupportedDraftSnapshot(t *testing.T) {
	plugin := New()
	_, err := plugin.Issue(context.Background(), profile.IssueRequest{
		ProfileVersion: "fips-206-draft",
	})
	if err == nil {
		t.Fatalf("expected unsupported draft error")
	}
}

func TestVerifyRejectsWrongArtifactType(t *testing.T) {
	plugin := New()
	artifact, publicKey := signedArtifactWithType(t, plugin, "wrong-fndsa-artifact")
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
