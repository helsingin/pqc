package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
	// Explicit controls for a reproducible probe. An empty list uses Go defaults.
	CurvePreferences []tls.CurveID
	MinVersion       uint16
	MaxVersion       uint16
	// Numeric IP:port only. Verification and SNI still use ServerName/target host.
	DialAddress string
	NextProtos  []string
}

type TLSReport struct {
	RemoteAddress           string           `json:"remote_address,omitempty"`
	OfferedKeyExchanges     []string         `json:"offered_key_exchanges,omitempty"`
	MinTLSVersion           string           `json:"min_tls_version,omitempty"`
	MaxTLSVersion           string           `json:"max_tls_version,omitempty"`
	NegotiatedProtocol      string           `json:"negotiated_protocol,omitempty"`
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
	SerialNumberHex     string            `json:"serial_number_hex"`
	PublicKeySHA256     string            `json:"public_key_sha256"`
	Subject             string            `json:"subject"`
	Issuer              string            `json:"issuer"`
	DNSNames            []string          `json:"dns_names,omitempty"`
	NotBefore           time.Time         `json:"not_before"`
	NotAfter            time.Time         `json:"not_after"`
	SignatureAlgorithm  string            `json:"signature_algorithm"`
	PublicKeyAlgorithm  string            `json:"public_key_algorithm"`
	FingerprintSHA256   string            `json:"fingerprint_sha256"`
	RawBytes            int               `json:"raw_bytes"`
	RawDER              []byte            `json:"raw_der,omitempty"`
	SignatureOID        string            `json:"signature_oid,omitempty"`
	PublicKeyOID        string            `json:"public_key_oid,omitempty"`
	PublicKeyParameters map[string]string `json:"public_key_parameters,omitempty"`
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
	minVersion, maxVersion := opts.MinVersion, opts.MaxVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	if maxVersion == 0 {
		maxVersion = tls.VersionTLS13
	}
	if minVersion < tls.VersionTLS12 || maxVersion > tls.VersionTLS13 || minVersion > maxVersion {
		return TLSReport{}, fmt.Errorf("TLS inspection supports TLS 1.2 through TLS 1.3")
	}
	if opts.PQC && len(opts.CurvePreferences) > 0 {
		return TLSReport{}, fmt.Errorf("choose PQC defaults or explicit groups, not both")
	}
	cfg := &tls.Config{MinVersion: minVersion, MaxVersion: maxVersion, ServerName: serverName, RootCAs: opts.RootCAs, NextProtos: append([]string(nil), opts.NextProtos...), CurvePreferences: append([]tls.CurveID(nil), opts.CurvePreferences...)}
	if opts.PQC {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519, tls.CurveP256, tls.CurveP384}
	}
	destination := networkTarget
	if opts.DialAddress != "" {
		address, port, err := net.SplitHostPort(opts.DialAddress)
		number, e := strconv.Atoi(port)
		if err != nil || e != nil || number < 1 || number > 65535 || net.ParseIP(address) == nil {
			return TLSReport{}, fmt.Errorf("dial address must be numeric IP:port")
		}
		destination = opts.DialAddress
	}
	// Capture trust failure on the same connection, rather than reconnecting to
	// a potentially different frontend. TLS handshake signature checks still run.
	// Inspection sends no application data. This is not a general-purpose TLS dialer.
	var verificationErr error
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if opts.InsecureSkipVerify {
			return nil
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, verificationErr = state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: opts.RootCAs, Intermediates: intermediates})
		return nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	netConn, err := dialer.DialContext(dialCtx, "tcp", destination)
	if err != nil {
		return TLSReport{}, err
	}
	conn, ok := netConn.(*tls.Conn)
	if !ok {
		netConn.Close()
		return TLSReport{}, fmt.Errorf("unexpected TLS connection type %T", netConn)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	report := tlsReportFromState(networkTarget, serverName, state, time.Now().UTC())
	report.RemoteAddress = conn.RemoteAddr().String()
	report.MinTLSVersion = tlsVersionName(minVersion)
	report.MaxTLSVersion = tlsVersionName(maxVersion)
	report.NegotiatedProtocol = state.NegotiatedProtocol
	for _, group := range cfg.CurvePreferences {
		report.OfferedKeyExchanges = append(report.OfferedKeyExchanges, group.String())
	}
	report.VerificationMode = tlsVerificationMode(opts)
	report.Verified = !opts.InsecureSkipVerify && verificationErr == nil
	if verificationErr != nil {
		report.VerificationError = verificationErr.Error()
		report.Warnings = append(report.Warnings, "certificate verification failed")
	}
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
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	out := TLSCertificate{SerialNumberHex: cert.SerialNumber.Text(16), PublicKeySHA256: hex.EncodeToString(spkiSum[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), DNSNames: append([]string(nil), cert.DNSNames...), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), SignatureAlgorithm: cert.SignatureAlgorithm.String(), PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), FingerprintSHA256: hex.EncodeToString(sum[:]), RawBytes: len(cert.Raw), RawDER: append([]byte(nil), cert.Raw...), PublicKeyParameters: map[string]string{}}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.Raw, &outer); err == nil && len(rest) == 0 {
		out.SignatureOID = outer.Algorithm.Algorithm.String()
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil && len(rest) == 0 {
		out.PublicKeyOID = spki.Algorithm.Algorithm.String()
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		out.PublicKeyParameters["bits"] = strconv.Itoa(key.N.BitLen())
	case *ecdsa.PublicKey:
		out.PublicKeyParameters["curve"] = key.Curve.Params().Name
		out.PublicKeyParameters["bits"] = strconv.Itoa(key.Curve.Params().BitSize)
	case ed25519.PublicKey:
		out.PublicKeyParameters["bits"] = strconv.Itoa(len(key) * 8)
	}
	return out
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
