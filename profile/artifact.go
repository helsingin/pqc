package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	pqc "github.com/helsingin/pqc"
)

var artifactSignatureContext = []byte(ArtifactSchema)

func SignArtifact(ctx context.Context, signer Signer, signKey string, artifact *IssuedArtifact) error {
	if signer == nil {
		return fmt.Errorf("profile signer is required")
	}
	if signKey == "" {
		return fmt.Errorf("--sign-key is required")
	}
	message, err := ArtifactSigningMessage(artifact)
	if err != nil {
		return err
	}
	signature, err := signer.Sign(ctx, signKey, message, pqc.SignOptions{Context: artifactSignatureContext})
	if err != nil {
		return err
	}
	artifact.Signature = signature
	return nil
}

func VerifyArtifactSignature(artifact *IssuedArtifact, publicKey *pqc.PublicKey) error {
	if artifact == nil {
		return fmt.Errorf("profile artifact is required")
	}
	if artifact.Signature == nil {
		return fmt.Errorf("profile artifact is unsigned")
	}
	if publicKey == nil {
		return fmt.Errorf("public key is required to verify profile artifact")
	}
	message, err := ArtifactSigningMessage(artifact)
	if err != nil {
		return err
	}
	return pqc.VerifyWithPublicKey(*publicKey, message, artifact.Signature)
}

func ArtifactSigningMessage(artifact *IssuedArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, fmt.Errorf("profile artifact is required")
	}
	unsigned := struct {
		Schema         string          `json:"schema"`
		Profile        string          `json:"profile"`
		ProfileVersion string          `json:"profile_version,omitempty"`
		Type           string          `json:"type"`
		Subject        Subject         `json:"subject"`
		IssuedAt       time.Time       `json:"issued_at"`
		NotBefore      time.Time       `json:"not_before,omitempty"`
		NotAfter       time.Time       `json:"not_after,omitempty"`
		Inputs         json.RawMessage `json:"inputs,omitempty"`
		Metadata       map[string]any  `json:"metadata,omitempty"`
	}{
		Schema:         artifact.Schema,
		Profile:        artifact.Profile,
		ProfileVersion: artifact.ProfileVersion,
		Type:           artifact.Type,
		Subject:        artifact.Subject,
		IssuedAt:       artifact.IssuedAt.UTC(),
		NotBefore:      artifact.NotBefore.UTC(),
		NotAfter:       artifact.NotAfter.UTC(),
		Inputs:         normalizeRawJSON(artifact.Inputs),
		Metadata:       artifact.Metadata,
	}
	return json.Marshal(unsigned)
}

func normalizeRawJSON(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return append(json.RawMessage(nil), raw...)
	}
	return append(json.RawMessage(nil), buf.Bytes()...)
}
