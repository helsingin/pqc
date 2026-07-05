package core

import (
	"testing"
	"time"
)

func TestEvaluateTLSReadinessPublicWeb2029Ready(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	policy := PublicWeb2029TLSReadinessPolicy()
	report := TLSReport{
		Target:                "example.com:443",
		CertificateChainBytes: 2048,
		CertificateCount:      2,
		Verified:              true,
		Leaf: &TLSCertificate{
			DNSNames:           []string{"example.com"},
			NotBefore:          now.Add(-5 * 24 * time.Hour),
			NotAfter:           now.Add(35 * 24 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
		},
		Certificates: []TLSCertificate{
			{SignatureAlgorithm: "ECDSA-SHA256", PublicKeyAlgorithm: "ECDSA"},
			{SignatureAlgorithm: "SHA256-RSA", PublicKeyAlgorithm: "RSA"},
		},
	}

	readiness := EvaluateTLSReadiness(report, policy, now)
	if !readiness.ReadyFor47DayCerts {
		t.Fatalf("expected target to be ready: %+v", readiness)
	}
	if readiness.CertificateValidityDays != 40 {
		t.Fatalf("validity days = %d, want 40", readiness.CertificateValidityDays)
	}
	if readiness.DaysUntilExpiry != 35 {
		t.Fatalf("days until expiry = %d, want 35", readiness.DaysUntilExpiry)
	}
	if readiness.RenewalWindowRisk != "low" {
		t.Fatalf("renewal risk = %q, want low", readiness.RenewalWindowRisk)
	}
	if readiness.SANDCVReuseRisk != "low" {
		t.Fatalf("SAN/DCV risk = %q, want low", readiness.SANDCVReuseRisk)
	}
	if len(readiness.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", readiness.Findings)
	}
}

func TestEvaluateTLSReadinessPublicWeb2029AllowsMidCycleRenewalRisk(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	policy := PublicWeb2029TLSReadinessPolicy()
	report := TLSReport{
		Target:                "example.com:443",
		CertificateChainBytes: 2048,
		CertificateCount:      2,
		Verified:              true,
		Leaf: &TLSCertificate{
			DNSNames:           []string{"example.com"},
			NotBefore:          now.Add(-27 * 24 * time.Hour),
			NotAfter:           now.Add(20 * 24 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
		},
	}

	readiness := EvaluateTLSReadiness(report, policy, now)
	if !readiness.ReadyFor47DayCerts {
		t.Fatalf("expected 47-day certificate to remain ready mid-cycle: %+v", readiness)
	}
	if readiness.RenewalWindowRisk != "medium" {
		t.Fatalf("renewal risk = %q, want medium", readiness.RenewalWindowRisk)
	}
}

func TestEvaluateTLSReadinessPublicWeb2029FindsOperationalGaps(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	policy := PublicWeb2029TLSReadinessPolicy()
	dnsNames := make([]string, 30)
	for i := range dnsNames {
		dnsNames[i] = "host.example.com"
	}
	report := TLSReport{
		Target:                "example.com:443",
		CertificateChainBytes: 12 * 1024,
		CertificateCount:      3,
		Verified:              false,
		Leaf: &TLSCertificate{
			DNSNames:           dnsNames,
			NotBefore:          now.Add(-10 * 24 * time.Hour),
			NotAfter:           now.Add(80 * 24 * time.Hour),
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
		},
	}

	readiness := EvaluateTLSReadiness(report, policy, now)
	if readiness.ReadyFor47DayCerts {
		t.Fatalf("expected target to be not ready: %+v", readiness)
	}
	if readiness.CertificateValidityDays != 90 {
		t.Fatalf("validity days = %d, want 90", readiness.CertificateValidityDays)
	}
	if readiness.SANDCVReuseRisk != "high" {
		t.Fatalf("SAN/DCV risk = %q, want high", readiness.SANDCVReuseRisk)
	}
	for _, subject := range []string{"verification", "certificate_validity", "san_dcv_reuse", "chain_size"} {
		if !hasReadinessFinding(readiness.Findings, subject) {
			t.Fatalf("missing finding %q in %+v", subject, readiness.Findings)
		}
	}
}

func TestEvaluateTLSReadinessPublicWeb2029ExpiredCertificate(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	policy := PublicWeb2029TLSReadinessPolicy()
	report := TLSReport{
		Target:           "example.com:443",
		CertificateCount: 1,
		Verified:         true,
		Leaf: &TLSCertificate{
			DNSNames:           []string{"example.com"},
			NotBefore:          now.Add(-40 * 24 * time.Hour),
			NotAfter:           now,
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
		},
	}

	readiness := EvaluateTLSReadiness(report, policy, now)
	if readiness.ReadyFor47DayCerts {
		t.Fatalf("expected expired certificate to be not ready: %+v", readiness)
	}
	if readiness.RenewalWindowRisk != "expired" {
		t.Fatalf("renewal risk = %q, want expired", readiness.RenewalWindowRisk)
	}
	if !hasReadinessFinding(readiness.Findings, "certificate_expiry") {
		t.Fatalf("missing expiry finding: %+v", readiness.Findings)
	}
}

func hasReadinessFinding(findings []ReadinessFinding, subject string) bool {
	for _, finding := range findings {
		if finding.Subject == subject {
			return true
		}
	}
	return false
}
