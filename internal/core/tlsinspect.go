package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	TLSVerificationSystem  = "system"
	TLSVerificationCustom  = "custom"
	TLSVerificationSkipped = "skipped"
)

type TLSInspectOptions struct {
	ServerName         string
	Timeout            time.Duration
	InsecureSkipVerify bool
	PQC                bool
	RootCAs            *x509.CertPool
}

type TLSReport struct {
	Target                  string           `json:"target"`
	ServerName              string           `json:"server_name,omitempty"`
	TLSVersion              string           `json:"tls_version,omitempty"`
	CipherSuite             string           `json:"cipher_suite,omitempty"`
	KeyExchange             string           `json:"key_exchange,omitempty"`
	HybridPQCKeyExchange    bool             `json:"hybrid_pqc_key_exchange"`
	CertificateChainBytes   int              `json:"certificate_chain_bytes"`
	CertificateCount        int              `json:"certificate_count"`
	Verified                bool             `json:"verified"`
	VerificationMode        string           `json:"verification_mode,omitempty"`
	VerificationError       string           `json:"verification_error,omitempty"`
	Leaf                    *TLSCertificate  `json:"leaf,omitempty"`
	Certificates            []TLSCertificate `json:"certificates,omitempty"`
	SignedCertificateStamps int              `json:"signed_certificate_timestamps"`
	OCSPStapled             bool             `json:"ocsp_stapled"`
	ECHAccepted             bool             `json:"ech_accepted"`
	InspectedAt             time.Time        `json:"inspected_at"`
	Readiness               *TLSReadiness    `json:"readiness,omitempty"`
	Warnings                []string         `json:"warnings,omitempty"`
}

type TLSCertificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	RawBytes           int       `json:"raw_bytes"`
}

func InspectTLS(ctx context.Context, target string, opts TLSInspectOptions) (TLSReport, error) {
	networkTarget, host, err := normalizeTLSTarget(target)
	if err != nil {
		return TLSReport{}, err
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		RootCAs:            opts.RootCAs,
	}
	if opts.PQC {
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    cfg,
	}
	netConn, err := dialer.DialContext(dialCtx, "tcp", networkTarget)
	if err != nil {
		if opts.InsecureSkipVerify {
			return TLSReport{}, err
		}
		insecureOpts := opts
		insecureOpts.InsecureSkipVerify = true
		report, insecureErr := InspectTLS(ctx, networkTarget, insecureOpts)
		if insecureErr != nil {
			return TLSReport{}, err
		}
		report.Verified = false
		report.VerificationMode = tlsVerificationMode(opts)
		report.VerificationError = err.Error()
		report.Warnings = append(report.Warnings, "certificate verification failed")
		return report, nil
	}
	conn, ok := netConn.(*tls.Conn)
	if !ok {
		_ = netConn.Close()
		return TLSReport{}, fmt.Errorf("unexpected TLS connection type %T", netConn)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	state := conn.ConnectionState()
	report := tlsReportFromState(networkTarget, serverName, state, time.Now().UTC())
	report.VerificationMode = tlsVerificationMode(opts)
	report.Verified = len(state.VerifiedChains) > 0 && !opts.InsecureSkipVerify
	if opts.InsecureSkipVerify {
		report.Warnings = append(report.Warnings, "certificate verification skipped")
	}
	return report, nil
}

func tlsVerificationMode(opts TLSInspectOptions) string {
	if opts.InsecureSkipVerify {
		return TLSVerificationSkipped
	}
	if opts.RootCAs != nil {
		return TLSVerificationCustom
	}
	return TLSVerificationSystem
}

func tlsReportFromState(target, serverName string, state tls.ConnectionState, inspectedAt time.Time) TLSReport {
	report := TLSReport{
		Target:                  target,
		ServerName:              serverName,
		TLSVersion:              tlsVersionName(state.Version),
		CipherSuite:             tls.CipherSuiteName(state.CipherSuite),
		KeyExchange:             state.CurveID.String(),
		HybridPQCKeyExchange:    isHybridPQCGroup(state.CurveID),
		CertificateCount:        len(state.PeerCertificates),
		SignedCertificateStamps: len(state.SignedCertificateTimestamps),
		OCSPStapled:             len(state.OCSPResponse) > 0,
		ECHAccepted:             state.ECHAccepted,
		InspectedAt:             inspectedAt.UTC(),
	}
	for _, cert := range state.PeerCertificates {
		report.CertificateChainBytes += len(cert.Raw)
		out := tlsCertificate(cert)
		report.Certificates = append(report.Certificates, out)
	}
	if len(report.Certificates) > 0 {
		leaf := report.Certificates[0]
		report.Leaf = &leaf
		if inspectedAt.UTC().After(leaf.NotAfter) {
			report.Warnings = append(report.Warnings, "leaf certificate is expired")
		}
		if leaf.NotAfter.Sub(inspectedAt.UTC()) < 30*24*time.Hour {
			report.Warnings = append(report.Warnings, "leaf certificate expires within 30 days")
		}
	}
	if state.Version < tls.VersionTLS13 {
		report.Warnings = append(report.Warnings, "TLS 1.3 was not negotiated")
	}
	if !report.HybridPQCKeyExchange {
		report.Warnings = append(report.Warnings, "hybrid PQC key exchange was not negotiated")
	}
	return report
}

func normalizeTLSTarget(target string) (networkTarget, host string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("TLS target is required")
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil {
			return "", "", err
		}
		if parsed.Scheme != "https" {
			return "", "", fmt.Errorf("TLS target URL must use https")
		}
		if parsed.Host == "" {
			return "", "", fmt.Errorf("TLS target URL must include a host")
		}
		host = parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(host, port), host, nil
	}
	if strings.Count(target, ":") > 1 && !strings.HasPrefix(target, "[") {
		return net.JoinHostPort(target, "443"), target, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		return net.JoinHostPort(host, port), host, nil
	}
	if strings.Contains(err.Error(), "missing port in address") {
		host = strings.Trim(target, "[]")
		return net.JoinHostPort(host, "443"), host, nil
	}
	return "", "", err
}

func tlsCertificate(cert *x509.Certificate) TLSCertificate {
	sum := sha256.Sum256(cert.Raw)
	return TLSCertificate{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		DNSNames:           append([]string(nil), cert.DNSNames...),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  hex.EncodeToString(sum[:]),
		RawBytes:           len(cert.Raw),
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func isHybridPQCGroup(group tls.CurveID) bool {
	switch group {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}
