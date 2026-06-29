package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type ManifestPluginConfig struct {
	Metadata       Metadata
	ArtifactType   string
	DefaultVersion string
	DefaultTTL     time.Duration
	ArtifactMeta   map[string]any
	Estimates      []ArtifactEstimate
	Findings       []Finding
}

type ManifestPlugin struct {
	cfg ManifestPluginConfig
}

func NewManifestPlugin(cfg ManifestPluginConfig) *ManifestPlugin {
	if cfg.Metadata.ID == "" {
		panic("profile manifest plugin requires metadata id")
	}
	if cfg.ArtifactType == "" {
		panic("profile manifest plugin requires artifact type")
	}
	if cfg.DefaultVersion == "" {
		cfg.DefaultVersion = cfg.Metadata.DefaultVersion
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 90 * 24 * time.Hour
	}
	cfg.Metadata.Capabilities = Capabilities{
		Issue:    true,
		Verify:   true,
		Inspect:  true,
		Estimate: true,
	}
	if len(cfg.Metadata.ArtifactTypes) == 0 {
		cfg.Metadata.ArtifactTypes = []string{cfg.ArtifactType}
	}
	if cfg.Metadata.DefaultVersion == "" {
		cfg.Metadata.DefaultVersion = cfg.DefaultVersion
	}
	return &ManifestPlugin{cfg: cfg}
}

func (p *ManifestPlugin) ID() string {
	return p.cfg.Metadata.ID
}

func (p *ManifestPlugin) Metadata() Metadata {
	return p.cfg.Metadata
}

func (p *ManifestPlugin) Capabilities() Capabilities {
	return p.cfg.Metadata.Capabilities
}

func (p *ManifestPlugin) Issue(ctx context.Context, req IssueRequest) (*IssuedArtifact, error) {
	if req.Signer == nil {
		return nil, fmt.Errorf("profile %q requires a signer", p.ID())
	}
	if req.SignKey == "" {
		return nil, fmt.Errorf("profile %q requires --sign-key", p.ID())
	}
	issuedAt := req.IssuedAt.UTC()
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	notBefore := req.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = issuedAt
	}
	notAfter := req.NotAfter.UTC()
	if notAfter.IsZero() {
		notAfter = notBefore.Add(p.cfg.DefaultTTL)
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("not-after must be after not-before")
	}
	version := req.ProfileVersion
	if version == "" {
		version = p.cfg.DefaultVersion
	}
	artifactType := req.ArtifactType
	if artifactType == "" {
		artifactType = p.cfg.ArtifactType
	}
	inputs := normalizeRawJSON(req.Inputs)
	if len(inputs) == 0 {
		inputs = json.RawMessage(`{}`)
	}
	artifact := &IssuedArtifact{
		Schema:         ArtifactSchema,
		Profile:        p.ID(),
		ProfileVersion: version,
		Type:           artifactType,
		Subject:        req.Subject,
		IssuedAt:       issuedAt,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		Inputs:         inputs,
		Metadata:       p.artifactMetadata(),
	}
	if err := SignArtifact(ctx, req.Signer, req.SignKey, artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

func (p *ManifestPlugin) Verify(_ context.Context, req VerifyRequest) (*VerifyResult, error) {
	if req.Artifact == nil {
		return nil, fmt.Errorf("profile artifact is required")
	}
	result := &VerifyResult{
		Profile:  p.ID(),
		Artifact: req.Artifact.Type,
	}
	if req.Artifact.Schema != ArtifactSchema {
		result.Findings = append(result.Findings, p.finding("error", "schema", "unsupported profile artifact schema", nil))
		return result, fmt.Errorf("unsupported profile artifact schema %q", req.Artifact.Schema)
	}
	if req.Artifact.Profile != p.ID() {
		result.Findings = append(result.Findings, p.finding("error", "profile", "artifact profile does not match verifier", map[string]any{
			"artifact_profile": req.Artifact.Profile,
			"verifier_profile": p.ID(),
		}))
		return result, fmt.Errorf("artifact profile %q does not match verifier %q", req.Artifact.Profile, p.ID())
	}
	if err := VerifyArtifactSignature(req.Artifact, req.PublicKey); err != nil {
		result.Findings = append(result.Findings, p.finding("error", "signature", err.Error(), nil))
		return result, err
	}
	now := time.Now().UTC()
	if !req.Artifact.NotBefore.IsZero() && now.Before(req.Artifact.NotBefore) {
		result.Findings = append(result.Findings, p.finding("error", "validity", "artifact is not valid yet", nil))
		return result, fmt.Errorf("profile artifact is not valid before %s", req.Artifact.NotBefore.Format(time.RFC3339))
	}
	if !req.Artifact.NotAfter.IsZero() && now.After(req.Artifact.NotAfter) {
		result.Findings = append(result.Findings, p.finding("error", "validity", "artifact is expired", nil))
		return result, fmt.Errorf("profile artifact expired at %s", req.Artifact.NotAfter.Format(time.RFC3339))
	}
	result.OK = true
	return result, nil
}

func (p *ManifestPlugin) Inspect(_ context.Context, req InspectRequest) (*InspectResult, error) {
	findings := append([]Finding(nil), p.cfg.Findings...)
	if req.Target != "" {
		findings = append(findings, p.finding("info", req.Target, "profile inspection target recorded", nil))
	}
	return &InspectResult{
		Profile:  p.ID(),
		Findings: findings,
	}, nil
}

func (p *ManifestPlugin) Estimate(_ context.Context, _ EstimateRequest) (*EstimateResult, error) {
	return &EstimateResult{
		Profile:   p.ID(),
		Estimates: append([]ArtifactEstimate(nil), p.cfg.Estimates...),
		Findings:  append([]Finding(nil), p.cfg.Findings...),
	}, nil
}

func (p *ManifestPlugin) artifactMetadata() map[string]any {
	out := map[string]any{
		"profile":         p.ID(),
		"profile_status":  p.cfg.Metadata.Status,
		"standardization": p.cfg.Metadata.Standardization,
	}
	for key, value := range p.cfg.ArtifactMeta {
		out[key] = value
	}
	return out
}

func (p *ManifestPlugin) finding(severity, subject, message string, evidence map[string]any) Finding {
	return Finding{
		Profile:      p.ID(),
		Severity:     severity,
		Subject:      subject,
		Message:      message,
		Evidence:     evidence,
		Experimental: p.cfg.Metadata.Status != "stable",
	}
}
