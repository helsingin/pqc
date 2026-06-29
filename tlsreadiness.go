package pqc

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	TLSReadinessPolicyPublicWeb2029 = "public-web-2029"
)

type TLSReadinessPolicy struct {
	ID                             string    `json:"id"`
	Name                           string    `json:"name"`
	EffectiveDate                  time.Time `json:"effective_date"`
	MaxValidityDays                int       `json:"max_validity_days"`
	MaxDomainValidationReuseDays   int       `json:"max_domain_validation_reuse_days"`
	RecommendedRenewalCadenceDays  int       `json:"recommended_renewal_cadence_days"`
	RecommendedRenewalLeadTimeDays int       `json:"recommended_renewal_lead_time_days"`
	Source                         string    `json:"source"`
}

type TLSReadiness struct {
	Policy                         TLSReadinessPolicy `json:"policy"`
	Target                         string             `json:"target"`
	ReadyFor47DayCerts             bool               `json:"ready_for_47_day_certs"`
	CertificateValidityDays        int                `json:"certificate_validity_days"`
	DaysUntilExpiry                int                `json:"days_until_expiry"`
	RenewalWindowRisk              string             `json:"renewal_window_risk"`
	RecommendedRenewalCadenceDays  int                `json:"recommended_renewal_cadence_days"`
	RecommendedRenewalLeadTimeDays int                `json:"recommended_renewal_lead_time_days"`
	SANCount                       int                `json:"san_count"`
	SANDCVReuseRisk                string             `json:"san_dcv_reuse_risk"`
	SANDCVReuseRiskReason          string             `json:"san_dcv_reuse_risk_reason"`
	ChainSizeBytes                 int                `json:"chain_size_bytes"`
	CertificateCount               int                `json:"certificate_count"`
	LeafSignatureAlgorithm         string             `json:"leaf_signature_algorithm,omitempty"`
	LeafPublicKeyAlgorithm         string             `json:"leaf_public_key_algorithm,omitempty"`
	ChainSignatureAlgorithms       []string           `json:"chain_signature_algorithms,omitempty"`
	ChainPublicKeyAlgorithms       []string           `json:"chain_public_key_algorithms,omitempty"`
	HybridPQCKeyExchange           bool               `json:"hybrid_pqc_key_exchange"`
	Verified                       bool               `json:"verified"`
	Findings                       []ReadinessFinding `json:"findings,omitempty"`
}

type ReadinessFinding struct {
	Severity string         `json:"severity"`
	Subject  string         `json:"subject"`
	Message  string         `json:"message"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

func PublicWeb2029TLSReadinessPolicy() TLSReadinessPolicy {
	return TLSReadinessPolicy{
		ID:                             TLSReadinessPolicyPublicWeb2029,
		Name:                           "Public Web TLS 2029",
		EffectiveDate:                  time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC),
		MaxValidityDays:                47,
		MaxDomainValidationReuseDays:   10,
		RecommendedRenewalCadenceDays:  30,
		RecommendedRenewalLeadTimeDays: 17,
		Source:                         "CA/B Forum Ballot SC-081v3",
	}
}

func ResolveTLSReadinessPolicy(id string) (TLSReadinessPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "", TLSReadinessPolicyPublicWeb2029:
		return PublicWeb2029TLSReadinessPolicy(), nil
	default:
		return TLSReadinessPolicy{}, fmt.Errorf("unknown TLS readiness policy %q", id)
	}
}

func EvaluateTLSReadiness(report TLSReport, policy TLSReadinessPolicy, now time.Time) TLSReadiness {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	readiness := TLSReadiness{
		Policy:                         policy,
		Target:                         report.Target,
		RecommendedRenewalCadenceDays:  policy.RecommendedRenewalCadenceDays,
		RecommendedRenewalLeadTimeDays: policy.RecommendedRenewalLeadTimeDays,
		ChainSizeBytes:                 report.CertificateChainBytes,
		CertificateCount:               report.CertificateCount,
		HybridPQCKeyExchange:           report.HybridPQCKeyExchange,
		Verified:                       report.Verified,
	}
	signatureAlgorithms := map[string]bool{}
	publicKeyAlgorithms := map[string]bool{}
	for _, cert := range report.Certificates {
		signatureAlgorithms[cert.SignatureAlgorithm] = true
		publicKeyAlgorithms[cert.PublicKeyAlgorithm] = true
	}
	readiness.ChainSignatureAlgorithms = sortedKeys(signatureAlgorithms)
	readiness.ChainPublicKeyAlgorithms = sortedKeys(publicKeyAlgorithms)
	if report.Leaf == nil {
		readiness.RenewalWindowRisk = "unknown"
		readiness.SANDCVReuseRisk = "unknown"
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "error",
			Subject:  "certificate",
			Message:  "no leaf certificate was observed",
		})
		return readiness
	}

	leaf := *report.Leaf
	readiness.LeafSignatureAlgorithm = leaf.SignatureAlgorithm
	readiness.LeafPublicKeyAlgorithm = leaf.PublicKeyAlgorithm
	readiness.CertificateValidityDays = ceilDays(leaf.NotAfter.Sub(leaf.NotBefore))
	readiness.DaysUntilExpiry = ceilDays(leaf.NotAfter.Sub(now))
	readiness.SANCount = len(leaf.DNSNames)
	readiness.RenewalWindowRisk = renewalWindowRisk(readiness.DaysUntilExpiry, policy)
	readiness.SANDCVReuseRisk, readiness.SANDCVReuseRiskReason = sanDCVReuseRisk(readiness.SANCount, policy)
	readiness.ReadyFor47DayCerts = report.Verified &&
		readiness.CertificateValidityDays <= policy.MaxValidityDays &&
		readiness.DaysUntilExpiry > 0

	if !report.Verified {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "error",
			Subject:  "verification",
			Message:  "certificate chain was not verified",
		})
	}
	if readiness.CertificateValidityDays > policy.MaxValidityDays {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "warning",
			Subject:  "certificate_validity",
			Message:  "leaf certificate validity exceeds the public-web-2029 target",
			Evidence: map[string]any{
				"actual_days": readiness.CertificateValidityDays,
				"max_days":    policy.MaxValidityDays,
			},
		})
	}
	if readiness.DaysUntilExpiry <= 0 {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "error",
			Subject:  "certificate_expiry",
			Message:  "leaf certificate is expired",
			Evidence: map[string]any{
				"days_until_expiry": readabilityNonNegative(readiness.DaysUntilExpiry),
			},
		})
	} else if readiness.DaysUntilExpiry <= policy.RecommendedRenewalLeadTimeDays {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "warning",
			Subject:  "renewal_window",
			Message:  "leaf certificate is inside the recommended renewal lead-time window",
			Evidence: map[string]any{
				"days_until_expiry": readabilityNonNegative(readiness.DaysUntilExpiry),
				"lead_time_days":    policy.RecommendedRenewalLeadTimeDays,
			},
		})
	}
	if readiness.SANDCVReuseRisk != "low" {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "info",
			Subject:  "san_dcv_reuse",
			Message:  readiness.SANDCVReuseRiskReason,
			Evidence: map[string]any{
				"san_count":                    readiness.SANCount,
				"domain_validation_reuse_days": policy.MaxDomainValidationReuseDays,
				"risk":                         readiness.SANDCVReuseRisk,
			},
		})
	}
	if report.CertificateChainBytes > 10*1024 {
		readiness.Findings = append(readiness.Findings, ReadinessFinding{
			Severity: "warning",
			Subject:  "chain_size",
			Message:  "certificate chain is already above 10 KiB before PQ signature migration",
			Evidence: map[string]any{
				"chain_size_bytes": report.CertificateChainBytes,
			},
		})
	}
	return readiness
}

func ApplyTLSReadinessPolicy(report *InventoryReport, policyID string, now time.Time) error {
	if strings.TrimSpace(policyID) == "" {
		return nil
	}
	policy, err := ResolveTLSReadinessPolicy(policyID)
	if err != nil {
		return err
	}
	report.Policy = policy.ID
	for i := range report.Targets {
		readiness := EvaluateTLSReadiness(report.Targets[i], policy, now)
		report.Targets[i].Readiness = &readiness
		if !readiness.ReadyFor47DayCerts {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s is not ready for 47-day public TLS certificates", report.Targets[i].Target))
		}
	}
	return nil
}

func ceilDays(d time.Duration) int {
	days := int(math.Ceil(d.Hours() / 24))
	return days
}

func renewalWindowRisk(daysUntilExpiry int, policy TLSReadinessPolicy) string {
	switch {
	case daysUntilExpiry <= 0:
		return "expired"
	case daysUntilExpiry <= 7:
		return "critical"
	case daysUntilExpiry <= policy.RecommendedRenewalLeadTimeDays:
		return "high"
	case daysUntilExpiry <= policy.RecommendedRenewalCadenceDays:
		return "medium"
	default:
		return "low"
	}
}

func sanDCVReuseRisk(sanCount int, policy TLSReadinessPolicy) (string, string) {
	switch {
	case sanCount == 0:
		return "unknown", "no DNS SANs were visible; domain validation reuse risk cannot be inferred from TLS alone"
	case sanCount <= 5:
		return "low", "SAN set is small; 10-day domain validation reuse should be operationally manageable"
	case sanCount <= 25:
		return "medium", "SAN set is moderately large; 10-day domain validation reuse may require stronger automation"
	default:
		return "high", "SAN set is large; 10-day domain validation reuse is likely to require robust DCV automation"
	}
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func readabilityNonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
