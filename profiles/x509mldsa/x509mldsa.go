package x509mldsa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/helsingin/pqc/profile"
)

const (
	ID               = "x509-ml-dsa"
	Name             = "ML-DSA in X.509"
	SupportedVersion = "fips-204+rfc-9881"
	FIPS204          = "NIST FIPS 204"
	FIPS204Date      = "2024-08-13"
	RFC9881          = "IETF RFC 9881"
	RFC9881Date      = "2025-10"
	ArtifactType     = "x509-ml-dsa-certificate"

	defaultSignatureAlgorithm = "ml-dsa-44"
	defaultCertificateRole    = "leaf"
	defaultChainSignatures    = 5
	defaultChainPublicKeys    = 2
)

type Input struct {
	SignatureAlgorithm        string         `json:"signature_algorithm,omitempty"`
	SubjectPublicKeyAlgorithm string         `json:"subject_public_key_algorithm,omitempty"`
	CertificateRole           string         `json:"certificate_role,omitempty"`
	ChainSignatureCount       int            `json:"chain_signature_count,omitempty"`
	ChainPublicKeyCount       int            `json:"chain_public_key_count,omitempty"`
	Subject                   string         `json:"subject,omitempty"`
	DNSNames                  []string       `json:"dns_names,omitempty"`
	KeyUsage                  []string       `json:"key_usage,omitempty"`
	ExtendedKeyUsage          []string       `json:"extended_key_usage,omitempty"`
	Extensions                map[string]any `json:"extensions,omitempty"`
}

type AlgorithmInfo struct {
	Name                 string `json:"name"`
	OID                  string `json:"oid"`
	NISTSecurityCategory int    `json:"nist_security_category"`
	PublicKeyBytes       int    `json:"public_key_bytes"`
	SignatureBytes       int    `json:"signature_bytes"`
}

type Plugin struct {
	manifest *profile.ManifestPlugin
}

var algorithms = map[string]AlgorithmInfo{
	"ml-dsa-44": {
		Name:                 "ML-DSA-44",
		OID:                  "2.16.840.1.101.3.4.3.17",
		NISTSecurityCategory: 2,
		PublicKeyBytes:       1312,
		SignatureBytes:       2420,
	},
	"ml-dsa-65": {
		Name:                 "ML-DSA-65",
		OID:                  "2.16.840.1.101.3.4.3.18",
		NISTSecurityCategory: 3,
		PublicKeyBytes:       1952,
		SignatureBytes:       3309,
	},
	"ml-dsa-87": {
		Name:                 "ML-DSA-87",
		OID:                  "2.16.840.1.101.3.4.3.19",
		NISTSecurityCategory: 5,
		PublicKeyBytes:       2592,
		SignatureBytes:       4627,
	},
}

func init() {
	profile.Register(New())
}

func New() *Plugin {
	return &Plugin{manifest: profile.NewManifestPlugin(profile.ManifestPluginConfig{
		Metadata:       metadata(),
		ArtifactType:   ArtifactType,
		DefaultVersion: SupportedVersion,
		ArtifactMeta: map[string]any{
			"certificate_container":       "x509",
			"default_signature_algorithm": defaultSignatureAlgorithm,
			"drop_in_compatible":          true,
			"fips_standard":               FIPS204,
			"fips_standard_date":          FIPS204Date,
			"signature_family":            "ml-dsa",
			"supported_rfc":               RFC9881,
			"supported_rfc_date":          RFC9881Date,
			"tls_auth_overhead_bytes":     defaultTLSAuthOverhead(),
			"web_tls_viable":              false,
		},
		Estimates: estimates(defaultSignatureAlgorithm, defaultChainSignatures, defaultChainPublicKeys),
		Findings: []profile.Finding{{
			Profile:      ID,
			Severity:     "info",
			Subject:      "standardization",
			Message:      "ML-DSA in X.509 is pinned to finalized NIST FIPS 204 and IETF RFC 9881.",
			Evidence:     standardEvidence(),
			Experimental: false,
		}},
	})}
}

func (p *Plugin) ID() string {
	return ID
}

func (p *Plugin) Metadata() profile.Metadata {
	return p.manifest.Metadata()
}

func (p *Plugin) Capabilities() profile.Capabilities {
	return p.manifest.Capabilities()
}

func (p *Plugin) Issue(ctx context.Context, req profile.IssueRequest) (*profile.IssuedArtifact, error) {
	if err := validateVersion(req.ProfileVersion); err != nil {
		return nil, err
	}
	inputs, err := normalizeInputs(req.Inputs)
	if err != nil {
		return nil, err
	}
	req.ProfileVersion = SupportedVersion
	req.ArtifactType = ArtifactType
	req.Inputs = inputs
	return p.manifest.Issue(ctx, req)
}

func (p *Plugin) Verify(ctx context.Context, req profile.VerifyRequest) (*profile.VerifyResult, error) {
	result, err := p.manifest.Verify(ctx, req)
	if err != nil {
		return result, err
	}
	if req.Artifact.Type != ArtifactType {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "artifact_type", "artifact type is not supported by the ML-DSA X.509 profile", map[string]any{
			"artifact_type": req.Artifact.Type,
			"expected_type": ArtifactType,
		}))
		return result, fmt.Errorf("x509-ml-dsa artifact type %q is not supported; expected %s", req.Artifact.Type, ArtifactType)
	}
	if req.Artifact.ProfileVersion != SupportedVersion {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "supported_version", "artifact uses an unsupported ML-DSA X.509 standards version", map[string]any{
			"artifact_version":  req.Artifact.ProfileVersion,
			"supported_version": SupportedVersion,
			"fips_standard":     FIPS204,
			"supported_rfc":     RFC9881,
		}))
		return result, fmt.Errorf("x509-ml-dsa artifact version %q is not supported; expected %s", req.Artifact.ProfileVersion, SupportedVersion)
	}
	if _, err := normalizeInputs(req.Artifact.Inputs); err != nil {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "inputs", err.Error(), standardEvidence()))
		return result, err
	}
	result.Findings = append(result.Findings, finding("info", "supported_version", "verified against finalized ML-DSA X.509 standards", standardEvidence()))
	return result, nil
}

func (p *Plugin) Inspect(_ context.Context, req profile.InspectRequest) (*profile.InspectResult, error) {
	findings := []profile.Finding{
		finding("info", "supported_version", "ML-DSA X.509 artifact profile supports "+SupportedVersion, standardEvidence()),
	}
	if req.Target != "" {
		findings = append(findings, finding("info", req.Target, "ML-DSA X.509 inspection target recorded", nil))
	}
	if len(bytes.TrimSpace(req.Inputs)) != 0 {
		input, err := parseInputs(req.Inputs)
		if err != nil {
			findings = append(findings, finding("error", "inputs", err.Error(), nil))
		} else {
			findings = append(findings, inputFindings(input)...)
		}
	}
	return &profile.InspectResult{
		Profile:  ID,
		Findings: findings,
	}, nil
}

func (p *Plugin) Estimate(_ context.Context, req profile.EstimateRequest) (*profile.EstimateResult, error) {
	input := Input{
		SignatureAlgorithm:  defaultSignatureAlgorithm,
		ChainSignatureCount: defaultChainSignatures,
		ChainPublicKeyCount: defaultChainPublicKeys,
	}
	if len(bytes.TrimSpace(req.Inputs)) != 0 {
		var err error
		input, err = parseInputs(req.Inputs)
		if err != nil {
			return nil, err
		}
	}
	return &profile.EstimateResult{
		Profile:   ID,
		Estimates: estimates(input.SignatureAlgorithm, input.ChainSignatureCount, input.ChainPublicKeyCount),
		Findings: []profile.Finding{
			finding("info", "supported_version", "estimate is pinned to finalized FIPS 204 and RFC 9881", standardEvidence()),
			finding("warning", "web_tls_viability", "ML-DSA in X.509 is drop-in compatible, but the full-chain TLS authentication overhead is not viable for public web TLS", nil),
		},
	}, nil
}

func metadata() profile.Metadata {
	return profile.Metadata{
		ID:              ID,
		Name:            Name,
		Summary:         "Stable artifact profile for X.509 certificate artifacts using finalized ML-DSA identifiers.",
		Status:          "stable",
		Standardization: FIPS204 + "; " + RFC9881 + " Standards Track",
		BestFor:         []string{"private PKI", "enterprise PKI", "certificate chain sizing tests"},
		ArtifactTypes:   []string{ArtifactType},
		DefaultVersion:  SupportedVersion,
		References: []string{
			"https://csrc.nist.gov/pubs/fips/204/final",
			"https://www.rfc-editor.org/rfc/rfc9881.html",
			"https://datatracker.ietf.org/doc/rfc9881/",
		},
		Notes: []string{
			"Supports finalized " + FIPS204 + " dated " + FIPS204Date + ".",
			"Uses " + RFC9881 + " for ML-DSA X.509 certificates and CRLs.",
			"Drop-in compatible with X.509 encoding, but estimated full-chain web TLS authentication overhead is about 14.7 KB with ML-DSA-44.",
		},
		Parameters: map[string]any{
			"default_chain_public_keys":   defaultChainPublicKeys,
			"default_chain_signatures":    defaultChainSignatures,
			"default_signature_algorithm": defaultSignatureAlgorithm,
			"drop_in_compatible":          true,
			"fips_standard":               FIPS204,
			"fips_standard_date":          FIPS204Date,
			"rfc":                         RFC9881,
			"rfc_date":                    RFC9881Date,
			"supported_algorithms":        algorithmParameters(),
			"supported_version":           SupportedVersion,
			"tls_auth_overhead_ml_dsa_44": defaultTLSAuthOverhead(),
			"web_tls_viable":              false,
		},
	}
}

func normalizeInputs(raw json.RawMessage) (json.RawMessage, error) {
	input, err := parseInputs(raw)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func parseInputs(raw json.RawMessage) (Input, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	var input Input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return Input{}, fmt.Errorf("invalid ML-DSA X.509 input for %s: %w", SupportedVersion, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && err != io.EOF {
		return Input{}, fmt.Errorf("invalid ML-DSA X.509 input for %s: %w", SupportedVersion, err)
	} else if err == nil {
		return Input{}, fmt.Errorf("invalid ML-DSA X.509 input for %s: unexpected trailing JSON data", SupportedVersion)
	}
	if input.SignatureAlgorithm == "" {
		input.SignatureAlgorithm = defaultSignatureAlgorithm
	}
	input.SignatureAlgorithm = normalizeAlgorithm(input.SignatureAlgorithm)
	if _, ok := algorithms[input.SignatureAlgorithm]; !ok {
		return Input{}, fmt.Errorf("unsupported ML-DSA X.509 signature_algorithm %q", input.SignatureAlgorithm)
	}
	if input.SubjectPublicKeyAlgorithm == "" {
		input.SubjectPublicKeyAlgorithm = input.SignatureAlgorithm
	}
	input.SubjectPublicKeyAlgorithm = normalizeAlgorithm(input.SubjectPublicKeyAlgorithm)
	if _, ok := algorithms[input.SubjectPublicKeyAlgorithm]; !ok {
		return Input{}, fmt.Errorf("unsupported ML-DSA X.509 subject_public_key_algorithm %q", input.SubjectPublicKeyAlgorithm)
	}
	if input.CertificateRole == "" {
		input.CertificateRole = defaultCertificateRole
	}
	input.CertificateRole = strings.ToLower(strings.TrimSpace(input.CertificateRole))
	switch input.CertificateRole {
	case "leaf", "intermediate", "root":
	default:
		return Input{}, fmt.Errorf("unsupported ML-DSA X.509 certificate_role %q", input.CertificateRole)
	}
	if input.ChainSignatureCount == 0 {
		input.ChainSignatureCount = defaultChainSignatures
	}
	if input.ChainPublicKeyCount == 0 {
		input.ChainPublicKeyCount = defaultChainPublicKeys
	}
	if input.ChainSignatureCount < 0 {
		return Input{}, fmt.Errorf("chain_signature_count must be non-negative")
	}
	if input.ChainPublicKeyCount < 0 {
		return Input{}, fmt.Errorf("chain_public_key_count must be non-negative")
	}
	return input, nil
}

func validateVersion(version string) error {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "", SupportedVersion, "fips-204", "rfc-9881":
		return nil
	default:
		return fmt.Errorf("x509-ml-dsa supports %s; got --profile-version %s", SupportedVersion, version)
	}
}

func normalizeAlgorithm(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	return normalized
}

func estimates(algorithm string, signatureCount, publicKeyCount int) []profile.ArtifactEstimate {
	info := algorithms[algorithm]
	tlsAuthBytes := signatureCount*info.SignatureBytes + publicKeyCount*info.PublicKeyBytes
	return []profile.ArtifactEstimate{
		{
			ArtifactType: "x509-ml-dsa-certificate-chain",
			Metric:       "tls_auth_overhead",
			Value:        tlsAuthBytes,
			Unit:         "bytes",
			Notes: []string{
				"Full-chain TLS authentication estimate using ML-DSA X.509 public keys and signatures.",
				"Default ML-DSA-44 estimate is 5 signatures and 2 public keys: 14,724 bytes.",
			},
			Evidence: map[string]any{
				"drop_in_compatible":  true,
				"public_key_bytes":    info.PublicKeyBytes,
				"public_key_count":    publicKeyCount,
				"signature_algorithm": algorithm,
				"signature_bytes":     info.SignatureBytes,
				"signature_count":     signatureCount,
				"supported_version":   SupportedVersion,
				"web_tls_viable":      false,
			},
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "signature_size",
			Value:        info.SignatureBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"oid":                 info.OID,
				"signature_algorithm": algorithm,
				"supported_rfc":       RFC9881,
			},
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "public_key_size",
			Value:        info.PublicKeyBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"oid":                          info.OID,
				"subject_public_key_algorithm": algorithm,
				"supported_rfc":                RFC9881,
			},
		},
	}
}

func inputFindings(input Input) []profile.Finding {
	info := algorithms[input.SignatureAlgorithm]
	return []profile.Finding{
		finding("info", "signature_algorithm", "ML-DSA X.509 signature algorithm accepted", map[string]any{
			"signature_algorithm":    input.SignatureAlgorithm,
			"oid":                    info.OID,
			"nist_security_category": info.NISTSecurityCategory,
			"supported_version":      SupportedVersion,
		}),
		finding("warning", "web_tls_viability", "drop-in X.509 compatibility does not make this viable for public web TLS handshakes", map[string]any{
			"estimated_tls_auth_overhead_bytes": input.ChainSignatureCount*info.SignatureBytes + input.ChainPublicKeyCount*info.PublicKeyBytes,
			"web_tls_viable":                    false,
		}),
	}
}

func finding(severity, subject, message string, evidence map[string]any) profile.Finding {
	return profile.Finding{
		Profile:      ID,
		Severity:     severity,
		Subject:      subject,
		Message:      message,
		Evidence:     evidence,
		Experimental: false,
	}
}

func standardEvidence() map[string]any {
	return map[string]any{
		"fips_standard":      FIPS204,
		"fips_standard_date": FIPS204Date,
		"supported_rfc":      RFC9881,
		"supported_rfc_date": RFC9881Date,
		"supported_version":  SupportedVersion,
	}
}

func defaultTLSAuthOverhead() int {
	info := algorithms[defaultSignatureAlgorithm]
	return defaultChainSignatures*info.SignatureBytes + defaultChainPublicKeys*info.PublicKeyBytes
}

func algorithmParameters() []AlgorithmInfo {
	return []AlgorithmInfo{
		algorithms["ml-dsa-44"],
		algorithms["ml-dsa-65"],
		algorithms["ml-dsa-87"],
	}
}
