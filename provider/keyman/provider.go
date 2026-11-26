//go:build cgo

// Package keyman adapts protected PKCS#11 signing to pqc.SigningProvider.
// Only this optional package requires Keyman's CGO/token integration. Private
// key material never enters a pqc Store and there is no software fallback.
package keyman

import (
	"bytes"
	"context"
	"fmt"
	"time"

	keyring "github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
	"github.com/helsingin/pqc"
)

// Provider uses an existing Keyman manager. The caller owns its lifecycle,
// token configuration and key creation/rotation/deletion policy.
type Provider struct{ manager *pkcs11.Manager }

var _ pqc.SigningProvider = (*Provider)(nil)

func New(manager *pkcs11.Manager) (*Provider, error) {
	if manager == nil {
		return nil, fmt.Errorf("keyman provider: manager is required")
	}
	return &Provider{manager: manager}, nil
}

func (p *Provider) bind(ctx context.Context, id string) (*pkcs11.Signer, *pqc.PublicKey, error) {
	if p == nil || p.manager == nil {
		return nil, nil, fmt.Errorf("keyman provider: manager is required")
	}
	signer, err := p.manager.ManagedSigner(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("keyman provider: bind key: %w", err)
	}
	key := signer.Key()
	var algorithm pqc.Algorithm
	var raw []byte
	switch key.Type {
	case keyring.KeyTypeMLDSA65:
		algorithm = pqc.AlgorithmMLDSA65
		if pub, ok := signer.Public().(pkcs11.MLDSA65PublicKey); ok {
			raw = pub
		}
	case keyring.KeyTypeMLDSA87:
		algorithm = pqc.AlgorithmMLDSA87
		if pub, ok := signer.Public().(pkcs11.MLDSA87PublicKey); ok {
			raw = pub
		}
	case keyring.KeyTypeSLHDSASHA2192s:
		algorithm = pqc.AlgorithmSLHDSASHA2192s
		if pub, ok := signer.Public().(pkcs11.SLHDSASHA2192sPublicKey); ok {
			raw = pub
		}
	case keyring.KeyTypeSLHDSASHA2256s:
		algorithm = pqc.AlgorithmSLHDSASHA2256s
		if pub, ok := signer.Public().(pkcs11.SLHDSASHA2256sPublicKey); ok {
			raw = pub
		}
	default:
		return nil, nil, fmt.Errorf("keyman provider: %w: %s", keyring.ErrUnsupportedKeyType, key.Type)
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("keyman provider: public key type does not match %s", key.Type)
	}
	created := key.CreatedAt
	if key.Version > 1 {
		created = key.RotatedAt
	}
	public := &pqc.PublicKey{ID: key.ID, Version: key.Version, Algorithm: algorithm, Use: pqc.KeyUseSignature, PublicKey: bytes.Clone(raw), CreatedAt: created.UTC()}
	return signer, public, nil
}

// Sign captures one key version before signing. Rotation may advance the
// manager while that version signs, but cannot relabel its signature. False
// Randomized requires deterministic signing; true requires token randomness.
// Tokens that cannot honor the context/mode return an error, never a fallback.
func (p *Provider) Sign(ctx context.Context, id string, message []byte, opts pqc.SignOptions) (*pqc.SignatureEnvelope, error) {
	if len(opts.Context) > 255 {
		return nil, fmt.Errorf("keyman provider: %w: context exceeds 255 bytes", pkcs11.ErrUnsupportedPQOperation)
	}
	signer, public, err := p.bind(ctx, id)
	if err != nil {
		return nil, err
	}
	contextBytes := bytes.Clone(opts.Context)
	mode := pkcs11.PQDeterministic
	if opts.Randomized {
		mode = pkcs11.PQRandomized
	}
	signature, err := signer.SignContext(ctx, message, pkcs11.PQSigningOptions{Context: contextBytes, Mode: mode})
	if err != nil {
		return nil, fmt.Errorf("keyman provider: sign: %w", err)
	}
	return &pqc.SignatureEnvelope{Schema: pqc.SignatureSchema, KeyID: public.ID, KeyVersion: public.Version, Algorithm: public.Algorithm, Context: contextBytes, Signature: signature, CreatedAt: time.Now().UTC()}, nil
}

// ExportPublic exports only the current public verification key. Preserve this
// result before rotating when historical evidence must remain verifiable.
func (p *Provider) ExportPublic(ctx context.Context, id string) (*pqc.PublicKey, error) {
	_, public, err := p.bind(ctx, id)
	return public, err
}
