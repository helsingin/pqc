package pqc

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ReadinessScanSchema = "pqc.readiness-scan.v1"
)

type ReadinessScan struct {
	Schema     string              `json:"schema"`
	CreatedAt  time.Time           `json:"created_at"`
	Policy     string              `json:"policy,omitempty"`
	Score      int                 `json:"score"`
	Level      string              `json:"level"`
	Coverage   ReadinessCoverage   `json:"coverage"`
	Summary    string              `json:"summary"`
	Categories []ReadinessCategory `json:"categories"`
	Findings   []ReadinessFinding  `json:"findings,omitempty"`
	Inventory  InventoryReport     `json:"inventory"`
}

type ReadinessCategory struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Applies     bool           `json:"applies"`
	ScoreImpact int            `json:"score_impact"`
	Summary     string         `json:"summary"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

type ReadinessCoverage struct {
	Confidence                       string `json:"confidence"`
	ScoreImpact                      int    `json:"score_impact"`
	KeyStoreScanned                  bool   `json:"key_store_scanned"`
	KeyCount                         int    `json:"key_count"`
	TLSTargetsScanned                bool   `json:"tls_targets_scanned"`
	TLSTargetCount                   int    `json:"tls_target_count"`
	TLSLifecycleReadinessTargetCount int    `json:"tls_lifecycle_readiness_target_count"`
	SystemVerifiedTargetCount        int    `json:"system_verified_target_count"`
	CustomVerifiedTargetCount        int    `json:"custom_verified_target_count"`
	UnverifiedTargetCount            int    `json:"unverified_target_count"`
}

func BuildReadinessScan(report InventoryReport, now time.Time) ReadinessScan {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	scan := ReadinessScan{
		Schema:    ReadinessScanSchema,
		CreatedAt: now,
		Policy:    report.Policy,
		Score:     100,
		Inventory: report,
	}
	if len(report.Keys) == 0 && len(report.Targets) == 0 {
		scan.Coverage = buildReadinessCoverage(report, localKeySummary{}, targetReadinessSummary{})
		scan.Score = 0
		scan.Level = "unknown"
		scan.Summary = "no key store entries or TLS targets were scanned"
		scan.Categories = defaultUnknownReadinessCategories()
		scan.Findings = append(scan.Findings, ReadinessFinding{
			Severity: "warning",
			Subject:  "input",
			Message:  "readiness scan had no keys or targets to evaluate",
		})
		return scan
	}

	local := summarizeLocalKeys(report.Keys)
	targets := summarizeReadinessTargets(report.Targets)
	scan.Coverage = buildReadinessCoverage(report, local, targets)
	scan.Categories = []ReadinessCategory{
		classicalOnlyCategory(local, targets),
		hybridKEXReadyCategory(targets),
		pqSignatureExperimentalCategory(local, targets),
		webPKIMTCCandidateCategory(targets),
		privatePKIPQX509CandidateCategory(local, targets),
		automationRiskCategory(targets),
		chainSizeRiskCategory(targets),
	}
	for _, category := range scan.Categories {
		scan.Score += category.ScoreImpact
		if category.ScoreImpact < 0 {
			scan.Findings = append(scan.Findings, ReadinessFinding{
				Severity: readinessSeverity(category.Status),
				Subject:  category.ID,
				Message:  category.Summary,
				Evidence: category.Evidence,
			})
		}
	}
	scan.Score += scan.Coverage.ScoreImpact
	if scan.Coverage.ScoreImpact < 0 {
		scan.Findings = append(scan.Findings, ReadinessFinding{
			Severity: "warning",
			Subject:  "coverage",
			Message:  "readiness score is based on partial scan coverage",
			Evidence: map[string]any{
				"confidence":   scan.Coverage.Confidence,
				"score_impact": scan.Coverage.ScoreImpact,
			},
		})
	}
	if scan.Score < 0 {
		scan.Score = 0
	}
	if scan.Score > 100 {
		scan.Score = 100
	}
	scan.Level = readinessLevel(scan.Score)
	scan.Summary = readinessSummary(scan)
	return scan
}

type localKeySummary struct {
	Total        int
	PQKEM        int
	PQSignatures int
	Algorithms   []string
}

type targetReadinessSummary struct {
	Total                int
	Verified             int
	SystemVerified       int
	CustomVerified       int
	SkippedVerification  int
	Unverified           int
	HybridKEX            int
	PQSignatureTargets   int
	ClassicalOnlyTargets int
	WebPKICandidates     int
	PrivatePKICandidates int
	ReadinessTargets     int
	AutomationMedium     int
	AutomationHigh       int
	ChainSizeMedium      int
	ChainSizeHigh        int
	MaxChainSizeBytes    int
	Targets              []string
}

func summarizeLocalKeys(keys []InventoryEntry) localKeySummary {
	summary := localKeySummary{Total: len(keys)}
	algorithms := map[string]bool{}
	for _, key := range keys {
		algorithms[string(key.Algorithm)] = true
		switch key.Algorithm {
		case AlgorithmMLKEM768:
			summary.PQKEM++
		case AlgorithmMLDSA65, AlgorithmMLDSA87:
			summary.PQSignatures++
		}
	}
	summary.Algorithms = sortedKeys(algorithms)
	return summary
}

func summarizeReadinessTargets(targets []TLSReport) targetReadinessSummary {
	summary := targetReadinessSummary{Total: len(targets)}
	for _, target := range targets {
		summary.Targets = append(summary.Targets, target.Target)
		mode := normalizedTLSVerificationMode(target)
		if target.Verified {
			summary.Verified++
			switch mode {
			case TLSVerificationSystem:
				summary.SystemVerified++
			case TLSVerificationCustom:
				summary.CustomVerified++
			}
		} else {
			summary.Unverified++
		}
		if mode == TLSVerificationSkipped {
			summary.SkippedVerification++
		}
		if target.HybridPQCKeyExchange {
			summary.HybridKEX++
		}
		if target.CertificateChainBytes > summary.MaxChainSizeBytes {
			summary.MaxChainSizeBytes = target.CertificateChainBytes
		}
		pqSignatures := tlsReportHasPQSignature(target)
		if pqSignatures {
			summary.PQSignatureTargets++
		}
		if !target.HybridPQCKeyExchange && !pqSignatures {
			summary.ClassicalOnlyTargets++
		}
		if target.Verified && mode == TLSVerificationSystem && target.Leaf != nil && len(target.Leaf.DNSNames) > 0 && !pqSignatures {
			summary.WebPKICandidates++
		}
		if !target.Verified || target.VerificationError != "" || mode == TLSVerificationCustom || mode == TLSVerificationSkipped {
			summary.PrivatePKICandidates++
		}
		if target.Readiness != nil {
			summary.ReadinessTargets++
			switch riskRank(target.Readiness.RenewalWindowRisk) {
			case 2:
				summary.AutomationMedium++
			case 3:
				summary.AutomationHigh++
			}
			switch riskRank(target.Readiness.SANDCVReuseRisk) {
			case 2:
				summary.AutomationMedium++
			case 3:
				summary.AutomationHigh++
			}
			if !target.Readiness.ReadyFor47DayCerts {
				summary.AutomationHigh++
			}
		}
		if target.CertificateChainBytes > 10*1024 {
			summary.ChainSizeHigh++
		} else if target.CertificateChainBytes > 7*1024 {
			summary.ChainSizeMedium++
		}
	}
	sort.Strings(summary.Targets)
	return summary
}

func classicalOnlyCategory(local localKeySummary, targets targetReadinessSummary) ReadinessCategory {
	applies := targets.Total > 0 && targets.ClassicalOnlyTargets == targets.Total
	category := ReadinessCategory{
		ID:      "classical-only",
		Applies: applies,
		Evidence: map[string]any{
			"local_pq_kem_keys":            local.PQKEM,
			"local_pq_signature_keys":      local.PQSignatures,
			"classical_only_target_count":  targets.ClassicalOnlyTargets,
			"scanned_tls_target_count":     targets.Total,
			"scanned_key_count":            local.Total,
			"observed_key_algorithms":      local.Algorithms,
			"observed_tls_target_examples": targets.Targets,
		},
	}
	if targets.Total == 0 && local.Total == 0 {
		category.Status = "unknown"
		category.Summary = "no keys or TLS targets were scanned"
		return category
	}
	if applies {
		category.Status = "fail"
		if local.PQKEM == 0 && local.PQSignatures == 0 {
			category.ScoreImpact = -25
			category.Summary = "only classical TLS authentication and no local PQ keys were observed"
			return category
		}
		category.ScoreImpact = -10
		category.Summary = "TLS targets are classical-only, although local PQ key material exists"
		return category
	}
	category.Status = "pass"
	category.Summary = "the scan observed either hybrid/PQ TLS behavior or local PQ key material"
	return category
}

func hybridKEXReadyCategory(targets targetReadinessSummary) ReadinessCategory {
	category := ReadinessCategory{
		ID:      "hybrid-kex-ready",
		Applies: targets.Total > 0 && targets.HybridKEX == targets.Total,
		Evidence: map[string]any{
			"hybrid_pqc_target_count":  targets.HybridKEX,
			"scanned_tls_target_count": targets.Total,
		},
	}
	switch {
	case targets.Total == 0:
		category.Status = "unknown"
		category.Summary = "no TLS targets were scanned"
	case targets.HybridKEX == targets.Total:
		category.Status = "pass"
		category.Summary = "all scanned TLS targets negotiated hybrid PQ key exchange"
	case targets.HybridKEX > 0:
		category.Status = "warn"
		category.ScoreImpact = -8
		category.Summary = "only some scanned TLS targets negotiated hybrid PQ key exchange"
	default:
		category.Status = "fail"
		category.ScoreImpact = -15
		category.Summary = "no scanned TLS target negotiated hybrid PQ key exchange"
	}
	return category
}

func pqSignatureExperimentalCategory(local localKeySummary, targets targetReadinessSummary) ReadinessCategory {
	applies := local.PQSignatures > 0 || targets.PQSignatureTargets > 0
	category := ReadinessCategory{
		ID:      "pq-signature-experimental",
		Applies: applies,
		Evidence: map[string]any{
			"local_pq_signature_keys":    local.PQSignatures,
			"pq_signature_target_count":  targets.PQSignatureTargets,
			"observed_key_algorithms":    local.Algorithms,
			"scanned_tls_target_count":   targets.Total,
			"scanned_local_key_count":    local.Total,
			"experimental_for_web_tls":   targets.PQSignatureTargets > 0,
			"local_artifact_signing_use": local.PQSignatures > 0,
		},
	}
	if !applies {
		category.Status = "info"
		category.Summary = "no PQ signature keys or PQ-signed TLS certificates were observed"
		return category
	}
	if targets.PQSignatureTargets > 0 {
		category.Status = "warn"
		category.ScoreImpact = -5
		category.Summary = "PQ signature material was observed on TLS targets; treat public-WebPKI use as experimental"
		return category
	}
	category.Status = "info"
	category.Summary = "local PQ signature keys exist for artifacts or private PKI experiments"
	return category
}

func webPKIMTCCandidateCategory(targets targetReadinessSummary) ReadinessCategory {
	applies := targets.WebPKICandidates > 0
	category := ReadinessCategory{
		ID:      "webpki-mtc-candidate",
		Applies: applies,
		Evidence: map[string]any{
			"candidate_target_count":   targets.WebPKICandidates,
			"system_verified_targets":  targets.SystemVerified,
			"custom_verified_targets":  targets.CustomVerified,
			"verified_target_count":    targets.Verified,
			"scanned_tls_targets":      targets.Total,
			"pq_signature_tls_targets": targets.PQSignatureTargets,
		},
	}
	if applies {
		category.Status = "info"
		category.Summary = "verified DNS-name TLS targets using non-PQ certificate signatures are plausible WebPKI MTC migration candidates"
		return category
	}
	category.Status = "unknown"
	category.Summary = "no verified DNS-name TLS target was identified as a WebPKI MTC candidate"
	return category
}

func privatePKIPQX509CandidateCategory(local localKeySummary, targets targetReadinessSummary) ReadinessCategory {
	applies := local.PQSignatures > 0 || targets.PrivatePKICandidates > 0
	category := ReadinessCategory{
		ID:      "private-pki-pq-x509-candidate",
		Applies: applies,
		Evidence: map[string]any{
			"local_pq_signature_keys":      local.PQSignatures,
			"private_candidate_targets":    targets.PrivatePKICandidates,
			"custom_verified_targets":      targets.CustomVerified,
			"skipped_verification_targets": targets.SkippedVerification,
			"unverified_targets":           targets.Unverified,
			"unverified_or_private_hint":   targets.PrivatePKICandidates > 0,
			"scanned_tls_target_count":     targets.Total,
			"scanned_local_key_count":      local.Total,
			"local_signature_key_present":  local.PQSignatures > 0,
		},
	}
	if applies {
		category.Status = "info"
		category.Summary = "local PQ signature keys or private/unverified TLS targets make private PKI PQ X.509 experimentation plausible"
		return category
	}
	category.Status = "unknown"
	category.Summary = "no local PQ signature key or private-PKI target signal was observed"
	return category
}

func buildReadinessCoverage(report InventoryReport, local localKeySummary, targets targetReadinessSummary) ReadinessCoverage {
	coverage := ReadinessCoverage{
		KeyStoreScanned:                  report.KeyStoreScanned,
		KeyCount:                         local.Total,
		TLSTargetsScanned:                targets.Total > 0,
		TLSTargetCount:                   targets.Total,
		TLSLifecycleReadinessTargetCount: targets.ReadinessTargets,
		SystemVerifiedTargetCount:        targets.SystemVerified,
		CustomVerifiedTargetCount:        targets.CustomVerified,
		UnverifiedTargetCount:            targets.Unverified,
	}
	switch {
	case local.Total == 0 && targets.Total == 0:
		coverage.Confidence = "empty"
	case targets.Total == 0:
		coverage.Confidence = "store-only"
		coverage.ScoreImpact = -20
	case targets.ReadinessTargets < targets.Total:
		coverage.Confidence = "limited"
		coverage.ScoreImpact = -10
	case !report.KeyStoreScanned:
		coverage.Confidence = "target-only"
	case targets.SystemVerified == 0 && targets.CustomVerified > 0:
		coverage.Confidence = "private-targets"
	default:
		coverage.Confidence = "full"
	}
	return coverage
}

func automationRiskCategory(targets targetReadinessSummary) ReadinessCategory {
	category := ReadinessCategory{
		ID:      "automation-risk",
		Applies: targets.AutomationMedium > 0 || targets.AutomationHigh > 0,
		Evidence: map[string]any{
			"medium_risk_signals":      targets.AutomationMedium,
			"high_risk_signals":        targets.AutomationHigh,
			"scanned_tls_target_count": targets.Total,
			"readiness_target_count":   targets.ReadinessTargets,
		},
	}
	switch {
	case targets.Total == 0:
		category.Status = "unknown"
		category.Summary = "no TLS lifecycle facts were scanned"
	case targets.ReadinessTargets == 0:
		category.Status = "unknown"
		category.Summary = "TLS targets were scanned without lifecycle readiness facts"
	case targets.AutomationHigh > 0:
		category.Status = "fail"
		category.ScoreImpact = -25
		category.Summary = "certificate lifecycle or DCV findings indicate high automation risk"
	case targets.AutomationMedium > 0:
		category.Status = "warn"
		category.ScoreImpact = -12
		category.Summary = "certificate lifecycle or DCV findings indicate medium automation risk"
	default:
		category.Status = "pass"
		category.Summary = "no material certificate automation risk was observed"
	}
	return category
}

func chainSizeRiskCategory(targets targetReadinessSummary) ReadinessCategory {
	category := ReadinessCategory{
		ID:      "chain-size-risk",
		Applies: targets.ChainSizeMedium > 0 || targets.ChainSizeHigh > 0,
		Evidence: map[string]any{
			"medium_risk_targets":       targets.ChainSizeMedium,
			"high_risk_targets":         targets.ChainSizeHigh,
			"max_chain_size_bytes":      targets.MaxChainSizeBytes,
			"medium_threshold_bytes":    7 * 1024,
			"high_threshold_bytes":      10 * 1024,
			"scanned_tls_target_count":  targets.Total,
			"pq_signature_size_context": "pre-PQ chains above these thresholds have less room for PQ signature overhead",
		},
	}
	switch {
	case targets.Total == 0:
		category.Status = "unknown"
		category.Summary = "no TLS certificate chains were scanned"
	case targets.ChainSizeHigh > 0:
		category.Status = "fail"
		category.ScoreImpact = -15
		category.Summary = "at least one certificate chain is already above 10 KiB before PQ signature migration"
	case targets.ChainSizeMedium > 0:
		category.Status = "warn"
		category.ScoreImpact = -8
		category.Summary = "at least one certificate chain is above 7 KiB before PQ signature migration"
	default:
		category.Status = "pass"
		category.Summary = "observed certificate chains are below the configured size-risk thresholds"
	}
	return category
}

func defaultUnknownReadinessCategories() []ReadinessCategory {
	ids := []string{
		"classical-only",
		"hybrid-kex-ready",
		"pq-signature-experimental",
		"webpki-mtc-candidate",
		"private-pki-pq-x509-candidate",
		"automation-risk",
		"chain-size-risk",
	}
	categories := make([]ReadinessCategory, 0, len(ids))
	for _, id := range ids {
		categories = append(categories, ReadinessCategory{
			ID:      id,
			Status:  "unknown",
			Summary: "no scan input was available for this category",
		})
	}
	return categories
}

func tlsReportHasPQSignature(report TLSReport) bool {
	if report.Leaf != nil && certificateHasPQSignature(*report.Leaf) {
		return true
	}
	for _, cert := range report.Certificates {
		if certificateHasPQSignature(cert) {
			return true
		}
	}
	return false
}

func certificateHasPQSignature(cert TLSCertificate) bool {
	values := []string{cert.SignatureAlgorithm, cert.PublicKeyAlgorithm}
	for _, value := range values {
		normalized := strings.ToLower(value)
		for _, token := range []string{"ml-dsa", "mldsa", "dilithium", "fn-dsa", "fndsa", "falcon", "sphincs", "slh-dsa", "composite"} {
			if strings.Contains(normalized, token) {
				return true
			}
		}
	}
	return false
}

func normalizedTLSVerificationMode(report TLSReport) string {
	mode := strings.ToLower(strings.TrimSpace(report.VerificationMode))
	switch mode {
	case TLSVerificationSystem, TLSVerificationCustom, TLSVerificationSkipped:
		return mode
	case "":
		if report.Verified {
			return TLSVerificationSystem
		}
		return ""
	default:
		return mode
	}
}

func riskRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "expired", "critical", "high":
		return 3
	case "medium", "unknown":
		return 2
	default:
		return 0
	}
}

func readinessSeverity(status string) string {
	switch status {
	case "fail":
		return "error"
	case "warn":
		return "warning"
	default:
		return "info"
	}
}

func readinessLevel(score int) string {
	switch {
	case score >= 80:
		return "ready"
	case score >= 60:
		return "watch"
	case score >= 40:
		return "at-risk"
	default:
		return "not-ready"
	}
}

func readinessSummary(scan ReadinessScan) string {
	var active []string
	var risks []string
	for _, category := range scan.Categories {
		if category.Applies {
			active = append(active, category.ID)
		}
		if category.ScoreImpact < 0 {
			risks = append(risks, category.ID)
		}
	}
	sort.Strings(active)
	sort.Strings(risks)
	if len(risks) > 0 {
		return fmt.Sprintf("%s readiness with risks: %s", scan.Level, strings.Join(risks, ", "))
	}
	if len(active) > 0 {
		return fmt.Sprintf("%s readiness with signals: %s", scan.Level, strings.Join(active, ", "))
	}
	return scan.Level + " readiness"
}
