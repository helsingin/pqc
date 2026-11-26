package core

import "context"

// Signer signs using a named, versioned key without requiring private-key export.
// Implementations must preserve the message and context, honor Randomized, and
// return an error when the requested operation is unavailable.
type Signer interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}

// SigningProvider adds public verification-key access to Signer. ExportPublic
// returns the current version; retain each public key needed for historical
// verification. Implementations must bind envelope metadata to the key used,
// including when rotation overlaps a signing operation.
type SigningProvider interface {
	Signer
	ExportPublic(context.Context, string) (*PublicKey, error)
}

var _ SigningProvider = (*Manager)(nil)
