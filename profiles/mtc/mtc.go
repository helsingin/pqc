package mtc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"strings"

	"github.com/helsingin/pqc/profile"
)

const (
	ID                    = "mtc"
	Name                  = "Merkle Tree Certificates"
	SupportedDraft        = "draft-ietf-plants-merkle-tree-certs-04"
	SupportedDraftDate    = "2026-05-24"
	SupportedDraftExpires = "2026-11-25"
	ArtifactType          = "merkle-tree-certificate"

	defaultHashAlgorithm = "sha256"
	landmarkCertificate  = "landmark"
	standaloneCert       = "standalone"
	defaultProofHashes   = 23
	sha256Bytes          = 32
)

type Input struct {
	CertificateType      string         `json:"certificate_type,omitempty"`
	TreeSize             uint64         `json:"tree_size,omitempty"`
	HashAlgorithm        string         `json:"hash_algorithm,omitempty"`
	LeafHash             string         `json:"leaf_hash,omitempty"`
	RootHash             string         `json:"root_hash,omitempty"`
	Checkpoint           string         `json:"checkpoint,omitempty"`
	CheckpointHash       string         `json:"checkpoint_hash,omitempty"`
	InclusionProof       []string       `json:"inclusion_proof,omitempty"`
	Landmark             string         `json:"landmark,omitempty"`
	Cosigners            []string       `json:"cosigners,omitempty"`
	SubjectPublicKeyHash string         `json:"subject_public_key_hash,omitempty"`
	RevocationIndex      uint64         `json:"revocation_index,omitempty"`
	Extensions           map[string]any `json:"extensions,omitempty"`
}

type Plugin struct {
	manifest *profile.ManifestPlugin
}

func init() {
	profile.Register(New())
}

func New() *Plugin {
	return &Plugin{manifest: profile.NewManifestPlugin(profile.ManifestPluginConfig{
		Metadata:       metadata(),
		ArtifactType:   ArtifactType,
		DefaultVersion: SupportedDraft,
		ArtifactMeta: map[string]any{
			"certificate_model":                "merkle-inclusion-proof",
			"drop_in_compatible":               false,
			"signatureless_landmark":           true,
			"supported_draft":                  SupportedDraft,
			"supported_draft_date":             SupportedDraftDate,
			"supported_draft_expires":          SupportedDraftExpires,
			"tls_auth_overhead_landmark_bytes": defaultProofHashes * sha256Bytes,
			"transparency_required":            true,
		},
		Estimates: estimates(defaultProofHashes),
		Findings: []profile.Finding{{
			Profile:      ID,
			Severity:     "info",
			Subject:      "standardization",
			Message:      "MTC support is pinned to " + SupportedDraft + ".",
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
	req.ProfileVersion = SupportedDraft
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
		result.Findings = append(result.Findings, finding("error", "artifact_type", "artifact type is not supported by the MTC profile", map[string]any{
			"artifact_type": req.Artifact.Type,
			"expected_type": ArtifactType,
		}))
		return result, fmt.Errorf("mtc artifact type %q is not supported; expected %s", req.Artifact.Type, ArtifactType)
	}
	if req.Artifact.ProfileVersion != SupportedDraft {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "supported_draft", "artifact uses an unsupported MTC draft version", map[string]any{
			"artifact_version": req.Artifact.ProfileVersion,
			"supported_draft":  SupportedDraft,
			"draft_date":       SupportedDraftDate,
			"draft_expires":    SupportedDraftExpires,
		}))
		return result, fmt.Errorf("mtc artifact version %q is not supported; expected %s", req.Artifact.ProfileVersion, SupportedDraft)
	}
	if _, err := normalizeInputs(req.Artifact.Inputs); err != nil {
		result.OK = false
		result.Findings = append(result.Findings, finding("error", "inputs", err.Error(), draftEvidence()))
		return result, err
	}
	result.Findings = append(result.Findings, finding("info", "supported_draft", "verified against supported MTC draft version", draftEvidence()))
	return result, nil
}

func (p *Plugin) Inspect(_ context.Context, req profile.InspectRequest) (*profile.InspectResult, error) {
	findings := []profile.Finding{
		finding("info", "supported_draft", "MTC artifact profile supports "+SupportedDraft, draftEvidence()),
	}
	if req.Target != "" {
		findings = append(findings, finding("info", req.Target, "MTC inspection target recorded", nil))
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
	proofHashes := defaultProofHashes
	if len(bytes.TrimSpace(req.Inputs)) != 0 {
		input, err := parseInputs(req.Inputs)
		if err != nil {
			return nil, err
		}
		if input.TreeSize > 0 {
			proofHashes = proofHashCount(input.TreeSize)
		}
	}
	return &profile.EstimateResult{
		Profile:   ID,
		Estimates: estimates(proofHashes),
		Findings: []profile.Finding{
			finding("info", "supported_draft", "estimate is pinned to "+SupportedDraft, draftEvidence()),
		},
	}, nil
}

func metadata() profile.Metadata {
	return profile.Metadata{
		ID:              ID,
		Name:            Name,
		Summary:         "Experimental artifact profile for PLANTS-style Merkle Tree Certificates.",
		Status:          "experimental",
		Standardization: "IETF PLANTS WG Internet-Draft " + SupportedDraft,
		BestFor:         []string{"browser HTTPS", "certificate transparency integrated issuance"},
		ArtifactTypes:   []string{ArtifactType},
		DefaultVersion:  SupportedDraft,
		References: []string{
			"https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/",
			"https://github.com/ietf-plants-wg/merkle-tree-certs",
		},
		Notes: []string{
			"Supports " + SupportedDraft + " dated " + SupportedDraftDate + "; the draft expires " + SupportedDraftExpires + ".",
			"Issues signed artifact profile documents for MTC workflow integration.",
			"Landmark-relative artifacts model the signatureless TLS authentication path.",
		},
		Parameters: map[string]any{
			"certificate_types":                []string{landmarkCertificate, standaloneCert},
			"default_certificate_type":         landmarkCertificate,
			"default_hash_algorithm":           defaultHashAlgorithm,
			"drop_in_compatible":               false,
			"supported_draft":                  SupportedDraft,
			"supported_draft_date":             SupportedDraftDate,
			"supported_draft_expires":          SupportedDraftExpires,
			"tls_auth_overhead_landmark_bytes": defaultProofHashes * sha256Bytes,
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
		return Input{}, fmt.Errorf("invalid MTC input for %s: %w", SupportedDraft, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && err != io.EOF {
		return Input{}, fmt.Errorf("invalid MTC input for %s: %w", SupportedDraft, err)
	} else if err == nil {
		return Input{}, fmt.Errorf("invalid MTC input for %s: unexpected trailing JSON data", SupportedDraft)
	}
	if input.CertificateType == "" {
		input.CertificateType = landmarkCertificate
	}
	input.CertificateType = strings.ToLower(strings.TrimSpace(input.CertificateType))
	switch input.CertificateType {
	case landmarkCertificate, standaloneCert:
	default:
		return Input{}, fmt.Errorf("invalid MTC certificate_type %q; expected %q or %q", input.CertificateType, landmarkCertificate, standaloneCert)
	}
	if input.HashAlgorithm == "" {
		input.HashAlgorithm = defaultHashAlgorithm
	}
	input.HashAlgorithm = normalizeHashAlgorithm(input.HashAlgorithm)
	if input.HashAlgorithm != defaultHashAlgorithm {
		return Input{}, fmt.Errorf("unsupported MTC hash_algorithm %q; expected %q", input.HashAlgorithm, defaultHashAlgorithm)
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{name: "leaf_hash", value: input.LeafHash},
		{name: "root_hash", value: input.RootHash},
		{name: "checkpoint_hash", value: input.CheckpointHash},
		{name: "subject_public_key_hash", value: input.SubjectPublicKeyHash},
	} {
		if err := validateOptionalSHA256(item.name, item.value); err != nil {
			return Input{}, err
		}
	}
	for i, value := range input.InclusionProof {
		if err := validateOptionalSHA256(fmt.Sprintf("inclusion_proof[%d]", i), value); err != nil {
			return Input{}, err
		}
	}
	return input, nil
}

func validateVersion(version string) error {
	if version == "" || version == SupportedDraft {
		return nil
	}
	return fmt.Errorf("mtc supports %s; got --profile-version %s", SupportedDraft, version)
}

func normalizeHashAlgorithm(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sha-256":
		return defaultHashAlgorithm
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func validateOptionalSHA256(name, value string) error {
	if value == "" {
		return nil
	}
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "sha256:")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s must be a SHA-256 hex value: %w", name, err)
	}
	if len(decoded) != sha256Bytes {
		return fmt.Errorf("%s must be %d bytes; got %d", name, sha256Bytes, len(decoded))
	}
	return nil
}

func proofHashCount(treeSize uint64) int {
	if treeSize <= 1 {
		return 0
	}
	return bits.Len64(treeSize - 1)
}

func estimates(proofHashes int) []profile.ArtifactEstimate {
	proofBytes := proofHashes * sha256Bytes
	return []profile.ArtifactEstimate{
		{
			ArtifactType: ArtifactType,
			Metric:       "tls_auth_overhead_landmark",
			Value:        proofBytes,
			Unit:         "bytes",
			Notes: []string{
				"Signatureless landmark-relative MTC authentication overhead.",
				"Default 736-byte estimate is 23 SHA-256 sibling hashes.",
			},
			Evidence: map[string]any{
				"drop_in_compatible": false,
				"hash_size_bytes":    sha256Bytes,
				"proof_hashes":       proofHashes,
				"supported_draft":    SupportedDraft,
			},
		},
		{
			ArtifactType: ArtifactType,
			Metric:       "landmark_inclusion_proof",
			Value:        proofBytes,
			Unit:         "bytes",
			Notes:        []string{"Estimated Merkle inclusion proof size for the landmark-relative artifact."},
			Evidence: map[string]any{
				"hash_size_bytes": sha256Bytes,
				"proof_hashes":    proofHashes,
				"supported_draft": SupportedDraft,
			},
		},
	}
}

func inputFindings(input Input) []profile.Finding {
	out := []profile.Finding{finding("info", "certificate_type", "MTC certificate type accepted", map[string]any{
		"certificate_type": input.CertificateType,
		"supported_draft":  SupportedDraft,
	})}
	if input.CertificateType == landmarkCertificate && len(input.InclusionProof) == 0 {
		out = append(out, finding("warning", "inclusion_proof", "landmark-relative MTC input does not include an inclusion proof yet", draftEvidence()))
	}
	if input.TreeSize > 0 {
		out = append(out, finding("info", "tree_size", "estimated MTC proof hash count from tree size", map[string]any{
			"tree_size":       input.TreeSize,
			"proof_hashes":    proofHashCount(input.TreeSize),
			"supported_draft": SupportedDraft,
		}))
	}
	return out
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
		"supported_draft":         SupportedDraft,
		"supported_draft_date":    SupportedDraftDate,
		"supported_draft_expires": SupportedDraftExpires,
	}
}
