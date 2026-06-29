package compositex509

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
	ID                    = "composite-x509"
	Name                  = "Composite X.509"
	SupportedDraft        = "draft-ietf-lamps-pq-composite-sigs-latest"
	SupportedDraftDate    = "2026-06-15"
	SupportedDraftExpires = "2026-12-17"
	SupportedVersion      = SupportedDraft + "@2026-06-15"
	ArtifactType          = "composite-x509-certificate"
	SourceURL             = "https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html"

	defaultCompositeAlgorithm = "id-MLDSA65-ECDSA-P256-SHA512"
	defaultCertificateRole    = "leaf"
	defaultChainSignatures    = 5
	defaultChainPublicKeys    = 2
	overheadRangeLow          = 17000
	overheadRangeHigh         = 20000
)

type Input struct {
	CompositeAlgorithm  string         `json:"composite_algorithm,omitempty"`
	CertificateRole     string         `json:"certificate_role,omitempty"`
	ChainSignatureCount int            `json:"chain_signature_count,omitempty"`
	ChainPublicKeyCount int            `json:"chain_public_key_count,omitempty"`
	Subject             string         `json:"subject,omitempty"`
	DNSNames            []string       `json:"dns_names,omitempty"`
	KeyUsage            []string       `json:"key_usage,omitempty"`
	ExtendedKeyUsage    []string       `json:"extended_key_usage,omitempty"`
	Extensions          map[string]any `json:"extensions,omitempty"`
}

type AlgorithmInfo struct {
	ID                string `json:"id"`
	OID               string `json:"oid"`
	Label             string `json:"label"`
	PreHash           string `json:"pre_hash"`
	MLDSA             string `json:"ml_dsa"`
	Traditional       string `json:"traditional"`
	PublicKeyBytes    int    `json:"public_key_bytes"`
	PrivateKeyBytes   int    `json:"private_key_bytes"`
	SignatureBytes    int    `json:"signature_bytes"`
	PublicKeyMaximum  bool   `json:"public_key_maximum,omitempty"`
	PrivateKeyMaximum bool   `json:"private_key_maximum,omitempty"`
	SignatureMaximum  bool   `json:"signature_maximum,omitempty"`
}

type Plugin struct {
	manifest *profile.ManifestPlugin
}

var algorithms = []AlgorithmInfo{
	{ID: "id-MLDSA44-RSA2048-PSS-SHA256", OID: "1.3.6.1.5.5.7.6.37", Label: "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", PreHash: "SHA256", MLDSA: "ML-DSA-44", Traditional: "RSA-2048-PSS", PublicKeyBytes: 1582, PrivateKeyBytes: 1226, SignatureBytes: 2676, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA44-RSA2048-PKCS15-SHA256", OID: "1.3.6.1.5.5.7.6.38", Label: "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", PreHash: "SHA256", MLDSA: "ML-DSA-44", Traditional: "RSA-2048-PKCS1-v1.5", PublicKeyBytes: 1582, PrivateKeyBytes: 1226, SignatureBytes: 2676, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA44-Ed25519-SHA512", OID: "1.3.6.1.5.5.7.6.39", Label: "COMPSIG-MLDSA44-Ed25519-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-44", Traditional: "Ed25519", PublicKeyBytes: 1344, PrivateKeyBytes: 64, SignatureBytes: 2484},
	{ID: "id-MLDSA44-ECDSA-P256-SHA256", OID: "1.3.6.1.5.5.7.6.40", Label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256", PreHash: "SHA256", MLDSA: "ML-DSA-44", Traditional: "ECDSA-P256", PublicKeyBytes: 1377, PrivateKeyBytes: 83, SignatureBytes: 2492, SignatureMaximum: true},
	{ID: "id-MLDSA65-RSA3072-PSS-SHA512", OID: "1.3.6.1.5.5.7.6.41", Label: "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "RSA-3072-PSS", PublicKeyBytes: 2350, PrivateKeyBytes: 1802, SignatureBytes: 3693, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA65-RSA3072-PKCS15-SHA512", OID: "1.3.6.1.5.5.7.6.42", Label: "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "RSA-3072-PKCS1-v1.5", PublicKeyBytes: 2350, PrivateKeyBytes: 1802, SignatureBytes: 3693, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA65-RSA4096-PSS-SHA512", OID: "1.3.6.1.5.5.7.6.43", Label: "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "RSA-4096-PSS", PublicKeyBytes: 2478, PrivateKeyBytes: 2383, SignatureBytes: 3821, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA65-RSA4096-PKCS15-SHA512", OID: "1.3.6.1.5.5.7.6.44", Label: "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "RSA-4096-PKCS1-v1.5", PublicKeyBytes: 2478, PrivateKeyBytes: 2383, SignatureBytes: 3821, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA65-ECDSA-P256-SHA512", OID: "1.3.6.1.5.5.7.6.45", Label: "COMPSIG-MLDSA65-ECDSA-P256-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "ECDSA-P256", PublicKeyBytes: 2017, PrivateKeyBytes: 83, SignatureBytes: 3381, SignatureMaximum: true},
	{ID: "id-MLDSA65-ECDSA-P384-SHA512", OID: "1.3.6.1.5.5.7.6.46", Label: "COMPSIG-MLDSA65-ECDSA-P384-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "ECDSA-P384", PublicKeyBytes: 2049, PrivateKeyBytes: 96, SignatureBytes: 3413, SignatureMaximum: true},
	{ID: "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", OID: "1.3.6.1.5.5.7.6.47", Label: "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "ECDSA-brainpoolP256r1", PublicKeyBytes: 2017, PrivateKeyBytes: 84, SignatureBytes: 3381, SignatureMaximum: true},
	{ID: "id-MLDSA65-Ed25519-SHA512", OID: "1.3.6.1.5.5.7.6.48", Label: "COMPSIG-MLDSA65-Ed25519-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-65", Traditional: "Ed25519", PublicKeyBytes: 1984, PrivateKeyBytes: 64, SignatureBytes: 3373},
	{ID: "id-MLDSA87-ECDSA-P384-SHA512", OID: "1.3.6.1.5.5.7.6.49", Label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-87", Traditional: "ECDSA-P384", PublicKeyBytes: 2689, PrivateKeyBytes: 96, SignatureBytes: 4731, SignatureMaximum: true},
	{ID: "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", OID: "1.3.6.1.5.5.7.6.50", Label: "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-87", Traditional: "ECDSA-brainpoolP384r1", PublicKeyBytes: 2689, PrivateKeyBytes: 100, SignatureBytes: 4731, SignatureMaximum: true},
	{ID: "id-MLDSA87-Ed448-SHAKE256", OID: "1.3.6.1.5.5.7.6.51", Label: "COMPSIG-MLDSA87-Ed448-SHAKE256", PreHash: "SHAKE256", MLDSA: "ML-DSA-87", Traditional: "Ed448", PublicKeyBytes: 2649, PrivateKeyBytes: 89, SignatureBytes: 4741},
	{ID: "id-MLDSA87-RSA3072-PSS-SHA512", OID: "1.3.6.1.5.5.7.6.52", Label: "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-87", Traditional: "RSA-3072-PSS", PublicKeyBytes: 2990, PrivateKeyBytes: 1802, SignatureBytes: 5011, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA87-RSA4096-PSS-SHA512", OID: "1.3.6.1.5.5.7.6.53", Label: "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-87", Traditional: "RSA-4096-PSS", PublicKeyBytes: 3118, PrivateKeyBytes: 2383, SignatureBytes: 5139, PublicKeyMaximum: true, PrivateKeyMaximum: true},
	{ID: "id-MLDSA87-ECDSA-P521-SHA512", OID: "1.3.6.1.5.5.7.6.54", Label: "COMPSIG-MLDSA87-ECDSA-P521-SHA512", PreHash: "SHA512", MLDSA: "ML-DSA-87", Traditional: "ECDSA-P521", PublicKeyBytes: 2725, PrivateKeyBytes: 114, SignatureBytes: 4766, SignatureMaximum: true},
}

var algorithmsByKey = func() map[string]AlgorithmInfo {
	out := make(map[string]AlgorithmInfo, len(algorithms))
	for _, algorithm := range algorithms {
		out[normalizeAlgorithm(algorithm.ID)] = algorithm
	}
	return out
}()

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
			"default_composite_algorithm": defaultCompositeAlgorithm,
			"drop_in_compatible":          true,
			"hybrid":                      true,
			"protocol_compatible":         true,
			"source":                      SourceURL,
			"supported_draft":             SupportedDraft,
			"supported_draft_date":        SupportedDraftDate,
			"supported_draft_expires":     SupportedDraftExpires,
			"tls_auth_overhead_range":     overheadRange(),
			"web_tls_viable":              false,
		},
		Estimates: estimates(defaultCompositeAlgorithm, defaultChainSignatures, defaultChainPublicKeys),
		Findings: []profile.Finding{{
			Profile:      ID,
			Severity:     "info",
			Subject:      "standardization",
			Message:      "Composite X.509 support is pinned to the LAMPS composite signatures snapshot published " + SupportedDraftDate + ".",
			Evidence:     draftEvidence(),
			Experimental: true,
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
		result.Findings = append(result.Findings, finding("error", "artifact_type", "artifact type is not supported by the Composite X.509 profile", map[string]any{
			"artifact_type": req.Artifact.Type,
			"expected_type": ArtifactType,
		}))
		return result, fmt.Errorf("composite-x509 artifact type %q is not supported; expected %s", req.Artifact.Type, ArtifactType)
	}
	if req.Artifact.ProfileVersion != SupportedVersion {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "supported_draft", "artifact uses an unsupported Composite ML-DSA draft snapshot", map[string]any{
			"artifact_version":  req.Artifact.ProfileVersion,
			"supported_version": SupportedVersion,
		}))
		return result, fmt.Errorf("composite-x509 artifact version %q is not supported; expected %s", req.Artifact.ProfileVersion, SupportedVersion)
	}
	if _, err := normalizeInputs(req.Artifact.Inputs); err != nil {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "inputs", err.Error(), draftEvidence()))
		return result, err
	}
	result.Findings = append(result.Findings, finding("info", "supported_draft", "verified against supported Composite ML-DSA draft snapshot", draftEvidence()))
	return result, nil
}

func (p *Plugin) Inspect(_ context.Context, req profile.InspectRequest) (*profile.InspectResult, error) {
	findings := []profile.Finding{
		finding("info", "supported_draft", "Composite X.509 artifact profile supports "+SupportedVersion, draftEvidence()),
	}
	if req.Target != "" {
		findings = append(findings, finding("info", req.Target, "Composite X.509 inspection target recorded", nil))
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
		CompositeAlgorithm:  defaultCompositeAlgorithm,
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
		Estimates: estimates(input.CompositeAlgorithm, input.ChainSignatureCount, input.ChainPublicKeyCount),
		Findings: []profile.Finding{
			finding("info", "supported_draft", "estimate is pinned to "+SupportedVersion, draftEvidence()),
			finding("warning", "web_tls_viability", "Composite X.509 is protocol-compatible, but the full-chain TLS authentication overhead is not viable for public web TLS", overheadRange()),
		},
	}, nil
}

func metadata() profile.Metadata {
	return profile.Metadata{
		ID:              ID,
		Name:            Name,
		Summary:         "Experimental artifact profile for LAMPS Composite ML-DSA X.509 certificate artifacts.",
		Status:          "experimental",
		Standardization: "IETF LAMPS Standards Track Internet-Draft " + SupportedDraft,
		BestFor:         []string{"enterprise PKI", "S/MIME", "VPN", "private TLS"},
		ArtifactTypes:   []string{ArtifactType},
		DefaultVersion:  SupportedVersion,
		References: []string{
			SourceURL,
			"https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/",
		},
		Notes: []string{
			"Supports " + SupportedDraft + " published " + SupportedDraftDate + "; the draft expires " + SupportedDraftExpires + ".",
			"Pins the generated latest source snapshot by publication date rather than treating latest as a floating target.",
			"Models Composite ML-DSA with RSA, ECDSA, Ed25519, and Ed448 component algorithms.",
			"Protocol-compatible with X.509/PKIX, but upgraded systems must understand the new composite OIDs.",
			"Best suited for enterprise PKI, S/MIME, VPN, and private TLS rather than public web TLS.",
		},
		Parameters: map[string]any{
			"default_chain_public_keys":   defaultChainPublicKeys,
			"default_chain_signatures":    defaultChainSignatures,
			"default_composite_algorithm": defaultCompositeAlgorithm,
			"drop_in_compatible":          true,
			"hybrid":                      true,
			"protocol_compatible":         true,
			"source":                      SourceURL,
			"supported_algorithm_count":   len(algorithms),
			"supported_algorithm_ids":     algorithmIDs(),
			"supported_draft":             SupportedDraft,
			"supported_draft_date":        SupportedDraftDate,
			"supported_draft_expires":     SupportedDraftExpires,
			"supported_version":           SupportedVersion,
			"tls_auth_overhead_range":     overheadRange(),
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
		return Input{}, fmt.Errorf("invalid Composite X.509 input for %s: %w", SupportedVersion, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && err != io.EOF {
		return Input{}, fmt.Errorf("invalid Composite X.509 input for %s: %w", SupportedVersion, err)
	} else if err == nil {
		return Input{}, fmt.Errorf("invalid Composite X.509 input for %s: unexpected trailing JSON data", SupportedVersion)
	}
	if input.CompositeAlgorithm == "" {
		input.CompositeAlgorithm = defaultCompositeAlgorithm
	}
	algorithm, err := resolveAlgorithm(input.CompositeAlgorithm)
	if err != nil {
		return Input{}, err
	}
	input.CompositeAlgorithm = algorithm.ID
	if input.CertificateRole == "" {
		input.CertificateRole = defaultCertificateRole
	}
	input.CertificateRole = strings.ToLower(strings.TrimSpace(input.CertificateRole))
	switch input.CertificateRole {
	case "leaf", "intermediate", "root", "csr", "crl":
	default:
		return Input{}, fmt.Errorf("unsupported Composite X.509 certificate_role %q", input.CertificateRole)
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
	case "", strings.ToLower(SupportedVersion), strings.ToLower(SupportedDraft):
		return nil
	default:
		return fmt.Errorf("composite-x509 supports %s; got --profile-version %s", SupportedVersion, version)
	}
}

func resolveAlgorithm(value string) (AlgorithmInfo, error) {
	algorithm, ok := algorithmsByKey[normalizeAlgorithm(value)]
	if !ok {
		return AlgorithmInfo{}, fmt.Errorf("unsupported Composite ML-DSA algorithm %q", value)
	}
	return algorithm, nil
}

func normalizeAlgorithm(value string) string {
	normalized := strings.TrimSpace(value)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return strings.ToLower(normalized)
}

func estimates(algorithmID string, signatureCount, publicKeyCount int) []profile.ArtifactEstimate {
	algorithm := algorithmsByKey[normalizeAlgorithm(algorithmID)]
	tlsAuthBytes := signatureCount*algorithm.SignatureBytes + publicKeyCount*algorithm.PublicKeyBytes
	return []profile.ArtifactEstimate{
		{
			ArtifactType: "composite-x509-certificate-chain",
			Metric:       "tls_auth_overhead",
			Value:        tlsAuthBytes,
			Unit:         "bytes",
			Notes: []string{
				"Full-chain TLS authentication estimate using draft maximum composite public-key and signature sizes.",
				"The table-level rule of thumb remains roughly 17-20 KB depending on selected composite algorithm and chain composition.",
			},
			Evidence: map[string]any{
				"composite_algorithm": algorithm.ID,
				"drop_in_compatible":  true,
				"protocol_compatible": true,
				"public_key_bytes":    algorithm.PublicKeyBytes,
				"public_key_count":    publicKeyCount,
				"signature_bytes":     algorithm.SignatureBytes,
				"signature_count":     signatureCount,
				"supported_version":   SupportedVersion,
				"web_tls_viable":      false,
			},
		},
		{
			ArtifactType: "composite-x509-certificate-chain",
			Metric:       "tls_auth_overhead_range_midpoint",
			Value:        (overheadRangeLow + overheadRangeHigh) / 2,
			Unit:         "bytes",
			Notes:        []string{"Rule-of-thumb range from the composite/hybrid X.509 migration table."},
			Evidence:     overheadRange(),
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "signature_size",
			Value:        algorithm.SignatureBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"composite_algorithm": algorithm.ID,
				"oid":                 algorithm.OID,
				"signature_maximum":   algorithm.SignatureMaximum,
				"source":              SourceURL,
			},
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "public_key_size",
			Value:        algorithm.PublicKeyBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"composite_algorithm": algorithm.ID,
				"oid":                 algorithm.OID,
				"public_key_maximum":  algorithm.PublicKeyMaximum,
				"source":              SourceURL,
			},
		},
	}
}

func inputFindings(input Input) []profile.Finding {
	algorithm := algorithmsByKey[normalizeAlgorithm(input.CompositeAlgorithm)]
	return []profile.Finding{
		finding("info", "composite_algorithm", "Composite ML-DSA algorithm accepted", map[string]any{
			"composite_algorithm": input.CompositeAlgorithm,
			"label":               algorithm.Label,
			"ml_dsa":              algorithm.MLDSA,
			"oid":                 algorithm.OID,
			"pre_hash":            algorithm.PreHash,
			"traditional":         algorithm.Traditional,
			"supported_version":   SupportedVersion,
		}),
		finding("warning", "web_tls_viability", "protocol compatibility does not make composite X.509 suitable for public web TLS handshakes", map[string]any{
			"estimated_tls_auth_overhead_bytes": input.ChainSignatureCount*algorithm.SignatureBytes + input.ChainPublicKeyCount*algorithm.PublicKeyBytes,
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
		Experimental: true,
	}
}

func draftEvidence() map[string]any {
	return map[string]any{
		"source":                  SourceURL,
		"supported_draft":         SupportedDraft,
		"supported_draft_date":    SupportedDraftDate,
		"supported_draft_expires": SupportedDraftExpires,
		"supported_version":       SupportedVersion,
	}
}

func overheadRange() map[string]any {
	return map[string]any{
		"low_bytes":      overheadRangeLow,
		"high_bytes":     overheadRangeHigh,
		"source":         "composite/hybrid X.509 migration table",
		"web_tls_viable": false,
	}
}

func algorithmIDs() []string {
	out := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		out = append(out, algorithm.ID)
	}
	return out
}
