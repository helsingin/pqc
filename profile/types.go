package profile

import (
	"context"
	"encoding/json"
	"time"

	pqc "github.com/helsingin/pqc"
)

const ArtifactSchema = "pqc.profile-artifact.v1"

type Capability string

const (
	CapabilityIssue    Capability = "issue"
	CapabilityVerify   Capability = "verify"
	CapabilityInspect  Capability = "inspect"
	CapabilityEstimate Capability = "estimate"
)

type Capabilities struct {
	Issue    bool `json:"issue"`
	Verify   bool `json:"verify"`
	Inspect  bool `json:"inspect"`
	Estimate bool `json:"estimate"`
}

type Metadata struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Summary         string         `json:"summary"`
	Status          string         `json:"status"`
	Standardization string         `json:"standardization,omitempty"`
	BestFor         []string       `json:"best_for,omitempty"`
	ArtifactTypes   []string       `json:"artifact_types,omitempty"`
	DefaultVersion  string         `json:"default_version,omitempty"`
	References      []string       `json:"references,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Capabilities    Capabilities   `json:"capabilities"`
	Parameters      map[string]any `json:"parameters,omitempty"`
}

type Subject struct {
	CommonName string   `json:"common_name,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	Emails     []string `json:"emails,omitempty"`
	URIs       []string `json:"uris,omitempty"`
}

type Signer interface {
	Sign(context.Context, string, []byte, pqc.SignOptions) (*pqc.SignatureEnvelope, error)
	ExportPublic(context.Context, string) (*pqc.PublicKey, error)
}

type IssueRequest struct {
	Profile        string          `json:"profile"`
	ProfileVersion string          `json:"profile_version,omitempty"`
	ArtifactType   string          `json:"artifact_type,omitempty"`
	Subject        Subject         `json:"subject"`
	Inputs         json.RawMessage `json:"inputs,omitempty"`
	SignKey        string          `json:"sign_key"`
	NotBefore      time.Time       `json:"not_before,omitempty"`
	NotAfter       time.Time       `json:"not_after,omitempty"`
	IssuedAt       time.Time       `json:"issued_at,omitempty"`
	Signer         Signer          `json:"-"`
}

type IssuedArtifact struct {
	Schema         string                 `json:"schema"`
	Profile        string                 `json:"profile"`
	ProfileVersion string                 `json:"profile_version,omitempty"`
	Type           string                 `json:"type"`
	Subject        Subject                `json:"subject"`
	IssuedAt       time.Time              `json:"issued_at"`
	NotBefore      time.Time              `json:"not_before,omitempty"`
	NotAfter       time.Time              `json:"not_after,omitempty"`
	Inputs         json.RawMessage        `json:"inputs,omitempty"`
	Metadata       map[string]any         `json:"metadata,omitempty"`
	Signature      *pqc.SignatureEnvelope `json:"signature,omitempty"`
}

type VerifyRequest struct {
	Artifact  *IssuedArtifact `json:"artifact"`
	PublicKey *pqc.PublicKey  `json:"-"`
}

type VerifyResult struct {
	OK       bool      `json:"ok"`
	Profile  string    `json:"profile"`
	Artifact string    `json:"artifact"`
	Findings []Finding `json:"findings,omitempty"`
}

type InspectRequest struct {
	Target string          `json:"target,omitempty"`
	Inputs json.RawMessage `json:"inputs,omitempty"`
}

type InspectResult struct {
	Profile  string    `json:"profile"`
	Findings []Finding `json:"findings,omitempty"`
}

type EstimateRequest struct {
	Inputs json.RawMessage `json:"inputs,omitempty"`
}

type EstimateResult struct {
	Profile   string             `json:"profile"`
	Estimates []ArtifactEstimate `json:"estimates,omitempty"`
	Findings  []Finding          `json:"findings,omitempty"`
}

type Finding struct {
	Profile      string         `json:"profile"`
	Severity     string         `json:"severity"`
	Subject      string         `json:"subject"`
	Message      string         `json:"message"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Experimental bool           `json:"experimental,omitempty"`
}

type ArtifactEstimate struct {
	ArtifactType string         `json:"artifact_type"`
	Metric       string         `json:"metric"`
	Value        int            `json:"value"`
	Unit         string         `json:"unit"`
	Notes        []string       `json:"notes,omitempty"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

type Plugin interface {
	ID() string
	Metadata() Metadata
	Capabilities() Capabilities
}

type Issuer interface {
	Issue(context.Context, IssueRequest) (*IssuedArtifact, error)
}

type Verifier interface {
	Verify(context.Context, VerifyRequest) (*VerifyResult, error)
}

type Inspector interface {
	Inspect(context.Context, InspectRequest) (*InspectResult, error)
}

type Estimator interface {
	Estimate(context.Context, EstimateRequest) (*EstimateResult, error)
}
