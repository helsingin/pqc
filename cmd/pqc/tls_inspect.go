package main

import (
	"fmt"
	"time"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runTLS(args []string) int {
	if len(args) == 0 {
		a.printTLSUsage()
		return 2
	}
	switch args[0] {
	case "inspect":
		return a.runTLSInspect(args[1:])
	case "readiness":
		return a.runTLSReadiness(args[1:])
	case "help", "-h", "--help":
		a.printTLSUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown tls command %q", args[0]), a.printTLSUsage)
	}
}

func (a *app) runTLSInspect(args []string) int {
	fs := a.flagSet("pqc tls inspect")
	jsonOut := fs.Bool("json", false, "write JSON report")
	serverName := fs.String("server-name", "", "override TLS server name")
	caFile := fs.String("ca", "", "CA PEM file for server verification")
	insecure := fs.Bool("insecure-skip-verify", false, "skip certificate verification")
	pqcPreferred := fs.Bool("pqc", true, "prefer hybrid PQC key exchange")
	timeout := fs.Duration("timeout", 10*time.Second, "inspection timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("tls inspect requires HOST:PORT"), a.printTLSUsage)
	}
	opts := pqc.TLSInspectOptions{
		ServerName:         *serverName,
		Timeout:            *timeout,
		InsecureSkipVerify: *insecure,
		PQC:                *pqcPreferred,
	}
	if *caFile != "" {
		pool, err := loadCertPool(*caFile)
		if err != nil {
			return a.fail(err)
		}
		opts.RootCAs = pool
	}
	report, err := pqc.InspectTLS(a.ctx, fs.Arg(0), opts)
	if err != nil {
		return a.fail(err)
	}
	if *jsonOut {
		return writeJSON(a.stdout, a.stderr, report)
	}
	printTLSReport(a, report)
	return 0
}

func (a *app) runTLSReadiness(args []string) int {
	fs := a.flagSet("pqc tls readiness")
	jsonOut := fs.Bool("json", false, "write JSON report")
	policyID := fs.String("policy", pqc.TLSReadinessPolicyPublicWeb2029, "readiness policy")
	serverName := fs.String("server-name", "", "override TLS server name")
	caFile := fs.String("ca", "", "CA PEM file for server verification")
	insecure := fs.Bool("insecure-skip-verify", false, "skip certificate verification")
	pqcPreferred := fs.Bool("pqc", true, "prefer hybrid PQC key exchange")
	timeout := fs.Duration("timeout", 10*time.Second, "inspection timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("tls readiness requires HOST:PORT"), a.printTLSUsage)
	}
	policy, err := pqc.ResolveTLSReadinessPolicy(*policyID)
	if err != nil {
		return a.fail(err)
	}
	opts := pqc.TLSInspectOptions{
		ServerName:         *serverName,
		Timeout:            *timeout,
		InsecureSkipVerify: *insecure,
		PQC:                *pqcPreferred,
	}
	if *caFile != "" {
		pool, err := loadCertPool(*caFile)
		if err != nil {
			return a.fail(err)
		}
		opts.RootCAs = pool
	}
	report, err := pqc.InspectTLS(a.ctx, fs.Arg(0), opts)
	if err != nil {
		return a.fail(err)
	}
	readiness := pqc.EvaluateTLSReadiness(report, policy, time.Now().UTC())
	report.Readiness = &readiness
	if *jsonOut {
		return writeJSON(a.stdout, a.stderr, report)
	}
	printTLSReadinessReport(a, report, readiness)
	return 0
}

func printTLSReport(a *app, report pqc.TLSReport) {
	_, _ = fmt.Fprintf(a.stdout, "target: %s\n", report.Target)
	_, _ = fmt.Fprintf(a.stdout, "tls: %s\n", report.TLSVersion)
	_, _ = fmt.Fprintf(a.stdout, "cipher_suite: %s\n", report.CipherSuite)
	_, _ = fmt.Fprintf(a.stdout, "key_exchange: %s\n", report.KeyExchange)
	_, _ = fmt.Fprintf(a.stdout, "hybrid_pqc_key_exchange: %t\n", report.HybridPQCKeyExchange)
	_, _ = fmt.Fprintf(a.stdout, "verified: %t\n", report.Verified)
	if report.VerificationMode != "" {
		_, _ = fmt.Fprintf(a.stdout, "verification_mode: %s\n", report.VerificationMode)
	}
	_, _ = fmt.Fprintf(a.stdout, "certificate_chain_bytes: %d\n", report.CertificateChainBytes)
	if report.Leaf != nil {
		_, _ = fmt.Fprintf(a.stdout, "leaf_subject: %s\n", report.Leaf.Subject)
		_, _ = fmt.Fprintf(a.stdout, "leaf_signature_algorithm: %s\n", report.Leaf.SignatureAlgorithm)
		_, _ = fmt.Fprintf(a.stdout, "leaf_public_key_algorithm: %s\n", report.Leaf.PublicKeyAlgorithm)
		_, _ = fmt.Fprintf(a.stdout, "leaf_not_after: %s\n", report.Leaf.NotAfter.Format(time.RFC3339))
	}
	if report.VerificationError != "" {
		_, _ = fmt.Fprintf(a.stdout, "verification_error: %s\n", report.VerificationError)
	}
	for _, warning := range report.Warnings {
		_, _ = fmt.Fprintf(a.stdout, "warning: %s\n", warning)
	}
}

func printTLSReadinessReport(a *app, report pqc.TLSReport, readiness pqc.TLSReadiness) {
	_, _ = fmt.Fprintf(a.stdout, "target: %s\n", report.Target)
	_, _ = fmt.Fprintf(a.stdout, "policy: %s\n", readiness.Policy.ID)
	_, _ = fmt.Fprintf(a.stdout, "ready_for_47_day_certs: %t\n", readiness.ReadyFor47DayCerts)
	_, _ = fmt.Fprintf(a.stdout, "certificate_validity_days: %d\n", readiness.CertificateValidityDays)
	_, _ = fmt.Fprintf(a.stdout, "days_until_expiry: %d\n", readiness.DaysUntilExpiry)
	_, _ = fmt.Fprintf(a.stdout, "renewal_window_risk: %s\n", readiness.RenewalWindowRisk)
	_, _ = fmt.Fprintf(a.stdout, "recommended_renewal_cadence_days: %d\n", readiness.RecommendedRenewalCadenceDays)
	_, _ = fmt.Fprintf(a.stdout, "recommended_renewal_lead_time_days: %d\n", readiness.RecommendedRenewalLeadTimeDays)
	_, _ = fmt.Fprintf(a.stdout, "san_count: %d\n", readiness.SANCount)
	_, _ = fmt.Fprintf(a.stdout, "san_dcv_reuse_risk: %s\n", readiness.SANDCVReuseRisk)
	_, _ = fmt.Fprintf(a.stdout, "certificate_chain_bytes: %d\n", readiness.ChainSizeBytes)
	_, _ = fmt.Fprintf(a.stdout, "certificate_count: %d\n", readiness.CertificateCount)
	_, _ = fmt.Fprintf(a.stdout, "leaf_signature_algorithm: %s\n", readiness.LeafSignatureAlgorithm)
	_, _ = fmt.Fprintf(a.stdout, "leaf_public_key_algorithm: %s\n", readiness.LeafPublicKeyAlgorithm)
	_, _ = fmt.Fprintf(a.stdout, "hybrid_pqc_key_exchange: %t\n", readiness.HybridPQCKeyExchange)
	_, _ = fmt.Fprintf(a.stdout, "verified: %t\n", readiness.Verified)
	if report.VerificationMode != "" {
		_, _ = fmt.Fprintf(a.stdout, "verification_mode: %s\n", report.VerificationMode)
	}
	for _, finding := range readiness.Findings {
		_, _ = fmt.Fprintf(a.stdout, "%s: %s: %s\n", finding.Severity, finding.Subject, finding.Message)
	}
}

func (a *app) printTLSUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc tls inspect [--json] [--server-name NAME] HOST:PORT
  pqc tls readiness [--json] [--policy public-web-2029] [--server-name NAME] HOST:PORT
`)
}
