package fndsa

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
	ID                    = "fndsa"
	Name                  = "FN-DSA"
	SupportedDraft        = "draft-ietf-lamps-fn-dsa-certificates-00"
	SupportedDraftDate    = "2026-05-20"
	SupportedDraftExpires = "2026-11-21"
	SupportedVersion      = SupportedDraft + "@2026-05-20"
	FIPS206               = "forthcoming NIST FIPS 206"
	ArtifactType          = "fndsa-certificate"
	SourceURL             = "https://www.ietf.org/archive/id/draft-ietf-lamps-fn-dsa-certificates-00.html"
	DatatrackerURL        = "https://datatracker.ietf.org/doc/draft-ietf-lamps-fn-dsa-certificates/"

	defaultParameterSet     = "fn-dsa-512"
	defaultCertificateRole  = "intermediate"
	defaultChainSignatures  = 5
	defaultChainPublicKeys  = 2
	overheadRangeLow        = 5000
	overheadRangeHigh       = 8000
	defaultFNDSAContext     = ""
	webTLSViable            = false
	webTLSViability         = "conditional"
	x509OIDAssignmentStatus = "tbd"
)

type Input struct {
	ParameterSet        string         `json:"parameter_set,omitempty"`
	CertificateRole     string         `json:"certificate_role,omitempty"`
	ChainSignatureCount int            `json:"chain_signature_count,omitempty"`
	ChainPublicKeyCount int            `json:"chain_public_key_count,omitempty"`
	PreHash             bool           `json:"pre_hash,omitempty"`
	ContextString       string         `json:"context_string,omitempty"`
	Subject             string         `json:"subject,omitempty"`
	DNSNames            []string       `json:"dns_names,omitempty"`
	KeyUsage            []string       `json:"key_usage,omitempty"`
	ExtendedKeyUsage    []string       `json:"extended_key_usage,omitempty"`
	Extensions          map[string]any `json:"extensions,omitempty"`
}

type ParameterSetInfo struct {
	ID                   string `json:"id"`
	Label                string `json:"label"`
	LegacyName           string `json:"legacy_name,omitempty"`
	OID                  string `json:"oid"`
	OIDStatus            string `json:"oid_status"`
	NISTSecurityCategory int    `json:"nist_security_category"`
	PublicKeyBytes       int    `json:"public_key_bytes"`
	SignatureBytes       int    `json:"signature_bytes"`
}

type Plugin struct {
	manifest *profile.ManifestPlugin
}

var parameterSets = []ParameterSetInfo{
	{
		ID:                   "fn-dsa-512",
		Label:                "FN-DSA-512",
		LegacyName:           "Falcon-512",
		OID:                  "TBD:id-fn-dsa-512",
		OIDStatus:            x509OIDAssignmentStatus,
		NISTSecurityCategory: 1,
		PublicKeyBytes:       897,
		SignatureBytes:       666,
	},
	{
		ID:                   "fn-dsa-1024",
		Label:                "FN-DSA-1024",
		LegacyName:           "Falcon-1024",
		OID:                  "TBD:id-fn-dsa-1024",
		OIDStatus:            x509OIDAssignmentStatus,
		NISTSecurityCategory: 5,
		PublicKeyBytes:       1793,
		SignatureBytes:       1280,
	},
}

var parameterSetsByKey = func() map[string]ParameterSetInfo {
	out := make(map[string]ParameterSetInfo, len(parameterSets)*2)
	for _, parameterSet := range parameterSets {
		out[normalizeParameterSet(parameterSet.ID)] = parameterSet
		out[normalizeParameterSet(parameterSet.Label)] = parameterSet
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
			"certificate_container":      "x509",
			"default_context_string":     defaultFNDSAContext,
			"default_parameter_set":      defaultParameterSet,
			"drop_in_compatible":         true,
			"fips_standard":              FIPS206,
			"hash_fn_dsa_allowed":        false,
			"signature_family":           "fn-dsa",
			"source":                     SourceURL,
			"supported_draft":            SupportedDraft,
			"supported_draft_date":       SupportedDraftDate,
			"supported_draft_expires":    SupportedDraftExpires,
			"tls_auth_overhead_range":    overheadRange(),
			"web_tls_viability":          webTLSViability,
			"web_tls_viable":             webTLSViable,
			"x509_oid_assignment_status": x509OIDAssignmentStatus,
		},
		Estimates: estimates(defaultParameterSet, defaultChainSignatures, defaultChainPublicKeys),
		Findings: []profile.Finding{{
			Profile:      ID,
			Severity:     "info",
			Subject:      "standardization",
			Message:      "FN-DSA X.509 support is pinned to " + SupportedDraft + "; FIPS 206 is still referenced as forthcoming by that draft.",
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
		result.Findings = append(result.Findings, finding("error", "artifact_type", "artifact type is not supported by the FN-DSA profile", map[string]any{
			"artifact_type": req.Artifact.Type,
			"expected_type": ArtifactType,
		}))
		return result, fmt.Errorf("fndsa artifact type %q is not supported; expected %s", req.Artifact.Type, ArtifactType)
	}
	if req.Artifact.ProfileVersion != SupportedVersion {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "supported_draft", "artifact uses an unsupported FN-DSA X.509 draft snapshot", map[string]any{
			"artifact_version":  req.Artifact.ProfileVersion,
			"supported_version": SupportedVersion,
		}))
		return result, fmt.Errorf("fndsa artifact version %q is not supported; expected %s", req.Artifact.ProfileVersion, SupportedVersion)
	}
	if _, err := normalizeInputs(req.Artifact.Inputs); err != nil {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "inputs", err.Error(), draftEvidence()))
		return result, err
	}
	result.Findings = append(result.Findings, finding("info", "supported_draft", "verified against supported FN-DSA X.509 draft snapshot", draftEvidence()))
	return result, nil
}

func (p *Plugin) Inspect(_ context.Context, req profile.InspectRequest) (*profile.InspectResult, error) {
	findings := []profile.Finding{
		finding("info", "supported_draft", "FN-DSA artifact profile supports "+SupportedVersion, draftEvidence()),
	}
	if req.Target != "" {
		findings = append(findings, finding("info", req.Target, "FN-DSA inspection target recorded", nil))
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
		ParameterSet:        defaultParameterSet,
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
		Estimates: estimates(input.ParameterSet, input.ChainSignatureCount, input.ChainPublicKeyCount),
		Findings: []profile.Finding{
			finding("info", "supported_draft", "estimate is pinned to "+SupportedVersion, draftEvidence()),
			finding("warning", "implementation_hardening", "FN-DSA signing implementations need side-channel and floating-point hardening before CA use", draftEvidence()),
		},
	}, nil
}

func metadata() profile.Metadata {
	return profile.Metadata{
		ID:              ID,
		Name:            Name,
		Summary:         "Experimental artifact profile for FN-DSA X.509 certificate and CRL artifacts.",
		Status:          "experimental",
		Standardization: FIPS206 + "; IETF LAMPS Internet-Draft " + SupportedDraft,
		BestFor:         []string{"root CAs", "intermediate CAs", "compact certificate chain experiments"},
		ArtifactTypes:   []string{ArtifactType},
		DefaultVersion:  SupportedVersion,
		References: []string{
			SourceURL,
			DatatrackerURL,
		},
		Notes: []string{
			"Supports " + SupportedDraft + " dated " + SupportedDraftDate + "; the draft expires " + SupportedDraftExpires + ".",
			"The draft references FIPS 206 as forthcoming; no public NIST FIPS 206 publication was found at implementation time.",
			"FN-DSA was previously known as Falcon, but the draft states FN-DSA and Falcon are not compatible.",
			"PKIX FN-DSA uses pure FN-DSA only; HashFN-DSA is intentionally rejected by this profile.",
			"Object identifiers are still TBD in the draft, so all OID handling stays inside this profile.",
		},
		Parameters: map[string]any{
			"default_chain_public_keys":  defaultChainPublicKeys,
			"default_chain_signatures":   defaultChainSignatures,
			"default_context_string":     defaultFNDSAContext,
			"default_parameter_set":      defaultParameterSet,
			"drop_in_compatible":         true,
			"fips_standard":              FIPS206,
			"hash_fn_dsa_allowed":        false,
			"source":                     SourceURL,
			"supported_draft":            SupportedDraft,
			"supported_draft_date":       SupportedDraftDate,
			"supported_draft_expires":    SupportedDraftExpires,
			"supported_parameter_sets":   parameterSetParameters(),
			"supported_version":          SupportedVersion,
			"tls_auth_overhead_range":    overheadRange(),
			"web_tls_viability":          webTLSViability,
			"web_tls_viable":             webTLSViable,
			"x509_oid_assignment_status": x509OIDAssignmentStatus,
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
		return Input{}, fmt.Errorf("invalid FN-DSA input for %s: %w", SupportedVersion, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && err != io.EOF {
		return Input{}, fmt.Errorf("invalid FN-DSA input for %s: %w", SupportedVersion, err)
	} else if err == nil {
		return Input{}, fmt.Errorf("invalid FN-DSA input for %s: unexpected trailing JSON data", SupportedVersion)
	}
	if input.ParameterSet == "" {
		input.ParameterSet = defaultParameterSet
	}
	parameterSet, err := resolveParameterSet(input.ParameterSet)
	if err != nil {
		return Input{}, err
	}
	input.ParameterSet = parameterSet.ID
	if input.CertificateRole == "" {
		input.CertificateRole = defaultCertificateRole
	}
	input.CertificateRole = strings.ToLower(strings.TrimSpace(input.CertificateRole))
	switch input.CertificateRole {
	case "leaf", "intermediate", "root", "csr", "crl", "ocsp":
	default:
		return Input{}, fmt.Errorf("unsupported FN-DSA certificate_role %q", input.CertificateRole)
	}
	if input.PreHash {
		return Input{}, fmt.Errorf("HashFN-DSA/pre-hash mode is not allowed by %s", SupportedDraft)
	}
	input.ContextString = strings.TrimSpace(input.ContextString)
	if input.ContextString != defaultFNDSAContext {
		return Input{}, fmt.Errorf("FN-DSA X.509 context_string must be empty for %s", SupportedDraft)
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
	if err := validateKeyUsage(input.KeyUsage); err != nil {
		return Input{}, err
	}
	return input, nil
}

func validateVersion(version string) error {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "", strings.ToLower(SupportedVersion), strings.ToLower(SupportedDraft):
		return nil
	default:
		return fmt.Errorf("fndsa supports %s; got --profile-version %s", SupportedVersion, version)
	}
}

func resolveParameterSet(value string) (ParameterSetInfo, error) {
	parameterSet, ok := parameterSetsByKey[normalizeParameterSet(value)]
	if !ok {
		return ParameterSetInfo{}, fmt.Errorf("unsupported FN-DSA parameter_set %q", value)
	}
	return parameterSet, nil
}

func normalizeParameterSet(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	normalized = strings.TrimPrefix(normalized, "id-")
	return normalized
}

func validateKeyUsage(values []string) error {
	allowed := map[string]bool{
		"digitalsignature":  true,
		"nonrepudiation":    true,
		"contentcommitment": true,
		"keycertsign":       true,
		"crlsign":           true,
	}
	for _, value := range values {
		normalized := normalizeKeyUsage(value)
		if !allowed[normalized] {
			return fmt.Errorf("unsupported FN-DSA key_usage %q; allowed values are digitalSignature, nonRepudiation/contentCommitment, keyCertSign, and cRLSign", value)
		}
	}
	return nil
}

func normalizeKeyUsage(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized
}

func estimates(parameterSetID string, signatureCount, publicKeyCount int) []profile.ArtifactEstimate {
	parameterSet := parameterSetsByKey[normalizeParameterSet(parameterSetID)]
	tlsAuthBytes := signatureCount*parameterSet.SignatureBytes + publicKeyCount*parameterSet.PublicKeyBytes
	return []profile.ArtifactEstimate{
		{
			ArtifactType: "fndsa-certificate-chain",
			Metric:       "tls_auth_overhead",
			Value:        tlsAuthBytes,
			Unit:         "bytes",
			Notes: []string{
				"Full-chain TLS authentication estimate using FN-DSA public-key sizes from the LAMPS draft and FN-DSA signature-size assumptions.",
				"The migration-table rule of thumb remains roughly 5-8 KB depending on parameter set and chain composition.",
			},
			Evidence: map[string]any{
				"drop_in_compatible": true,
				"parameter_set":      parameterSet.ID,
				"public_key_bytes":   parameterSet.PublicKeyBytes,
				"public_key_count":   publicKeyCount,
				"signature_bytes":    parameterSet.SignatureBytes,
				"signature_count":    signatureCount,
				"supported_version":  SupportedVersion,
				"web_tls_viability":  webTLSViability,
				"web_tls_viable":     webTLSViable,
				"x509_oid_status":    parameterSet.OIDStatus,
			},
		},
		{
			ArtifactType: "fndsa-certificate-chain",
			Metric:       "tls_auth_overhead_range_midpoint",
			Value:        (overheadRangeLow + overheadRangeHigh) / 2,
			Unit:         "bytes",
			Notes:        []string{"Rule-of-thumb range from the FN-DSA migration table."},
			Evidence:     overheadRange(),
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "signature_size",
			Value:        parameterSet.SignatureBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"oid":             parameterSet.OID,
				"parameter_set":   parameterSet.ID,
				"source":          SourceURL,
				"x509_oid_status": parameterSet.OIDStatus,
			},
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "public_key_size",
			Value:        parameterSet.PublicKeyBytes,
			Unit:         "bytes",
			Evidence: map[string]any{
				"oid":             parameterSet.OID,
				"parameter_set":   parameterSet.ID,
				"source":          SourceURL,
				"x509_oid_status": parameterSet.OIDStatus,
			},
		},
	}
}

func inputFindings(input Input) []profile.Finding {
	parameterSet := parameterSetsByKey[normalizeParameterSet(input.ParameterSet)]
	findings := []profile.Finding{
		finding("info", "parameter_set", "FN-DSA parameter set accepted", map[string]any{
			"legacy_name":            parameterSet.LegacyName,
			"nist_security_category": parameterSet.NISTSecurityCategory,
			"oid":                    parameterSet.OID,
			"parameter_set":          parameterSet.ID,
			"supported_version":      SupportedVersion,
			"x509_oid_status":        parameterSet.OIDStatus,
		}),
		finding("warning", "implementation_hardening", "FN-DSA CA signing should be limited to hardened implementations with side-channel controls", draftEvidence()),
	}
	if isCARole(input.CertificateRole) && parameterSet.NISTSecurityCategory < 5 {
		findings = append(findings, finding("warning", "security_category", "root and intermediate CA use should consider fn-dsa-1024 for a higher NIST security category", map[string]any{
			"certificate_role":       input.CertificateRole,
			"current_parameter_set":  parameterSet.ID,
			"nist_security_category": parameterSet.NISTSecurityCategory,
			"recommended_parameter":  "fn-dsa-1024",
		}))
	}
	return findings
}

func isCARole(role string) bool {
	switch role {
	case "root", "intermediate":
		return true
	default:
		return false
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
		"fips_standard":            FIPS206,
		"datatracker":              DatatrackerURL,
		"source":                   SourceURL,
		"supported_draft":          SupportedDraft,
		"supported_draft_date":     SupportedDraftDate,
		"supported_draft_expires":  SupportedDraftExpires,
		"supported_version":        SupportedVersion,
		"x509_oid_assignment_note": "id-fn-dsa-512 and id-fn-dsa-1024 are TBD in the supported draft",
	}
}

func overheadRange() map[string]any {
	return map[string]any{
		"high_bytes":        overheadRangeHigh,
		"low_bytes":         overheadRangeLow,
		"source":            "FN-DSA migration table",
		"web_tls_viability": webTLSViability,
		"web_tls_viable":    webTLSViable,
	}
}

func parameterSetParameters() []ParameterSetInfo {
	return append([]ParameterSetInfo(nil), parameterSets...)
}
