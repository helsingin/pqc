package pqc

import (
	"testing"
	"time"
)

func TestBuildReadinessScanFindsClassicalAutomationAndChainRisks(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	target := TLSReport{
		Target:                "example.com:443",
		TLSVersion:            "TLS 1.3",
		KeyExchange:           "X25519",
		Verified:              true,
		VerificationMode:      TLSVerificationSystem,
		CertificateChainBytes: 11 * 1024,
		CertificateCount:      2,
		Leaf: &TLSCertificate{
			Subject:            "CN=example.com",
			DNSNames:           []string{"example.com"},
			NotBefore:          now.Add(-80 * 24 * time.Hour),
			NotAfter:           now.Add(20 * 24 * time.Hour),
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			RawBytes:           2048,
		},
	}
	readiness := EvaluateTLSReadiness(target, PublicWeb2029TLSReadinessPolicy(), now)
	target.Readiness = &readiness
	report := BuildInventoryReport(nil, []TLSReport{target}, now)
	report.Policy = TLSReadinessPolicyPublicWeb2029

	scan := BuildReadinessScan(report, now)
	if scan.Schema != ReadinessScanSchema {
		t.Fatalf("schema = %q", scan.Schema)
	}
	if scan.Score >= 60 {
		t.Fatalf("score = %d, want risky score; scan = %+v", scan.Score, scan)
	}
	if scan.Level != "not-ready" && scan.Level != "at-risk" {
		t.Fatalf("level = %q", scan.Level)
	}
	for _, want := range []string{"classical-only", "automation-risk", "chain-size-risk"} {
		category := readinessCategoryByID(scan, want)
		if category == nil {
			t.Fatalf("missing category %q", want)
		}
		if !category.Applies {
			t.Fatalf("category %q does not apply: %+v", want, *category)
		}
		if category.ScoreImpact >= 0 {
			t.Fatalf("category %q did not reduce score: %+v", want, *category)
		}
	}
	if readinessCategoryByID(scan, "webpki-mtc-candidate").Applies != true {
		t.Fatalf("expected verified DNS TLS target to be an MTC candidate")
	}
}

func TestBuildReadinessScanRecognizesLocalPQKeyMaterial(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	target := TLSReport{
		Target:                  "service.internal:443",
		TLSVersion:              "TLS 1.3",
		KeyExchange:             "X25519MLKEM768",
		HybridPQCKeyExchange:    true,
		Verified:                true,
		VerificationMode:        TLSVerificationSystem,
		CertificateChainBytes:   2048,
		CertificateCount:        1,
		SignedCertificateStamps: 2,
		Leaf: &TLSCertificate{
			Subject:            "CN=service.internal",
			DNSNames:           []string{"service.internal"},
			NotBefore:          now.Add(-5 * 24 * time.Hour),
			NotAfter:           now.Add(35 * 24 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
			RawBytes:           1024,
		},
	}
	readiness := EvaluateTLSReadiness(target, PublicWeb2029TLSReadinessPolicy(), now)
	target.Readiness = &readiness
	keys := []KeyMetadata{
		{ID: "kem-a", Algorithm: AlgorithmMLKEM768, Use: KeyUseKEM, Version: 1, CreatedAt: now},
		{ID: "signer-a", Algorithm: AlgorithmMLDSA65, Use: KeyUseSignature, Version: 1, CreatedAt: now},
	}
	report := BuildInventoryReport(keys, []TLSReport{target}, now)
	report.Policy = TLSReadinessPolicyPublicWeb2029

	scan := BuildReadinessScan(report, now)
	if scan.Score != 100 {
		t.Fatalf("score = %d, findings = %+v", scan.Score, scan.Findings)
	}
	if !readinessCategoryByID(scan, "hybrid-kex-ready").Applies {
		t.Fatalf("expected hybrid-kex-ready category to apply")
	}
	if !readinessCategoryByID(scan, "pq-signature-experimental").Applies {
		t.Fatalf("expected local PQ signature category to apply")
	}
	if !readinessCategoryByID(scan, "private-pki-pq-x509-candidate").Applies {
		t.Fatalf("expected private PQ X.509 candidate category to apply")
	}
	if readinessCategoryByID(scan, "classical-only").Applies {
		t.Fatalf("did not expect classical-only category")
	}
}

func TestBuildReadinessScanTreatsCustomRootsAsPrivateCandidates(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	target := TLSReport{
		Target:                "internal.example:443",
		TLSVersion:            "TLS 1.3",
		KeyExchange:           "X25519",
		Verified:              true,
		VerificationMode:      TLSVerificationCustom,
		CertificateChainBytes: 2048,
		CertificateCount:      1,
		Leaf: &TLSCertificate{
			Subject:            "CN=internal.example",
			DNSNames:           []string{"internal.example"},
			NotBefore:          now.Add(-5 * 24 * time.Hour),
			NotAfter:           now.Add(35 * 24 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
			RawBytes:           1024,
		},
	}
	readiness := EvaluateTLSReadiness(target, PublicWeb2029TLSReadinessPolicy(), now)
	target.Readiness = &readiness
	report := BuildInventoryReport([]KeyMetadata{}, []TLSReport{target}, now)
	report.Policy = TLSReadinessPolicyPublicWeb2029

	scan := BuildReadinessScan(report, now)
	if readinessCategoryByID(scan, "webpki-mtc-candidate").Applies {
		t.Fatalf("custom-root target should not be a WebPKI MTC candidate: %+v", scan)
	}
	privateCategory := readinessCategoryByID(scan, "private-pki-pq-x509-candidate")
	if privateCategory == nil || !privateCategory.Applies {
		t.Fatalf("custom-root target should be a private PKI candidate: %+v", privateCategory)
	}
	if scan.Coverage.Confidence != "private-targets" {
		t.Fatalf("confidence = %q, want private-targets", scan.Coverage.Confidence)
	}
}

func TestBuildReadinessScanKeepsClassicalTargetRiskWithLocalPQKeys(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	target := TLSReport{
		Target:                "example.com:443",
		TLSVersion:            "TLS 1.3",
		KeyExchange:           "X25519",
		Verified:              true,
		VerificationMode:      TLSVerificationSystem,
		CertificateChainBytes: 2048,
		CertificateCount:      1,
		Leaf: &TLSCertificate{
			Subject:            "CN=example.com",
			DNSNames:           []string{"example.com"},
			NotBefore:          now.Add(-5 * 24 * time.Hour),
			NotAfter:           now.Add(35 * 24 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
			RawBytes:           1024,
		},
	}
	readiness := EvaluateTLSReadiness(target, PublicWeb2029TLSReadinessPolicy(), now)
	target.Readiness = &readiness
	report := BuildInventoryReport([]KeyMetadata{{
		ID:        "signer-a",
		Algorithm: AlgorithmMLDSA65,
		Use:       KeyUseSignature,
		Version:   1,
		CreatedAt: now,
	}}, []TLSReport{target}, now)
	report.Policy = TLSReadinessPolicyPublicWeb2029

	scan := BuildReadinessScan(report, now)
	category := readinessCategoryByID(scan, "classical-only")
	if category == nil || !category.Applies {
		t.Fatalf("expected classical-only category to still apply: %+v", category)
	}
	if category.ScoreImpact != -10 {
		t.Fatalf("score impact = %d, want reduced local-PQ impact", category.ScoreImpact)
	}
}

func TestBuildReadinessScanMarksAutomationUnknownWithoutLifecycleFacts(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	report := BuildInventoryReport(nil, []TLSReport{{
		Target:                "example.com:443",
		Verified:              true,
		VerificationMode:      TLSVerificationSystem,
		CertificateChainBytes: 2048,
		Leaf: &TLSCertificate{
			DNSNames:           []string{"example.com"},
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
		},
	}}, now)

	scan := BuildReadinessScan(report, now)
	category := readinessCategoryByID(scan, "automation-risk")
	if category == nil {
		t.Fatalf("missing automation category")
	}
	if category.Status != "unknown" {
		t.Fatalf("automation status = %q, want unknown", category.Status)
	}
	if category.ScoreImpact != 0 {
		t.Fatalf("automation score impact = %d", category.ScoreImpact)
	}
	if scan.Coverage.Confidence != "limited" {
		t.Fatalf("coverage confidence = %q, want limited", scan.Coverage.Confidence)
	}
}

func readinessCategoryByID(scan ReadinessScan, id string) *ReadinessCategory {
	for i := range scan.Categories {
		if scan.Categories[i].ID == id {
			return &scan.Categories[i]
		}
	}
	return nil
}
