package evidence

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/helsingin/pqc"
)

// SigningBytes implements the byte-exact encoding specified in docs/evidence-v2.md.
func SigningBytes(statement Statement) ([]byte, error) {
	if err := validateStatement(statement); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(Schema + "\x00")
	number := func(v uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); out.Write(b[:]) }
	text := func(v string) { number(uint64(len(v))); out.WriteString(v) }
	text(Schema)
	p := statement.Policy
	text(p.Schema)
	text(p.ID)
	number(uint64(p.Version))
	text(p.Purpose)
	text(p.Context)
	number(uint64(p.NotBefore))
	number(uint64(p.NotAfter))
	number(uint64(len(p.Signers)))
	for _, ref := range p.Signers {
		text(ref.KeyID)
		number(uint64(ref.KeyVersion))
		text(string(ref.Algorithm))
		text(ref.PublicKeyDigest)
	}
	text(statement.Payload.Hash)
	text(statement.Payload.Digest)
	number(statement.Payload.Length)
	text(statement.Payload.MediaType)
	number(uint64(statement.ClaimedAt))
	fields := append([]Field(nil), statement.Metadata...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Key < fields[j].Key })
	number(uint64(len(fields)))
	for _, field := range fields {
		text(field.Key)
		text(field.Value)
	}
	return out.Bytes(), nil
}

func policyEqual(a, b Policy) bool {
	if a.Schema != b.Schema || a.ID != b.ID || a.Version != b.Version || a.Purpose != b.Purpose || a.Context != b.Context || a.NotBefore != b.NotBefore || a.NotAfter != b.NotAfter || len(a.Signers) != len(b.Signers) {
		return false
	}
	for i := range a.Signers {
		if a.Signers[i] != b.Signers[i] {
			return false
		}
	}
	return true
}

// Sign requires one provider per policy signer, in policy order. Rotation to a
// different version fails explicitly. Any provider error returns no document.
// Earlier provider operations may have completed; Sign never retries them.
// Applications own operation reconciliation and audit policy.
func Sign(ctx context.Context, statement Statement, providers []pqc.SigningProvider, randomized bool) (*Envelope, error) {
	if ctx == nil {
		return nil, fmt.Errorf("evidence: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	statement.Policy.Signers = append([]SignerRef(nil), statement.Policy.Signers...)
	statement.Metadata = append([]Field{}, statement.Metadata...)
	message, err := SigningBytes(statement)
	if err != nil {
		return nil, err
	}
	if len(providers) != len(statement.Policy.Signers) {
		return nil, fmt.Errorf("evidence: provider count does not match policy")
	}
	result := &Envelope{Schema: Schema, Statement: statement, Signatures: make([]Signature, 0, len(providers))}
	for i, provider := range providers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if provider == nil || (reflect.ValueOf(provider).Kind() == reflect.Pointer && reflect.ValueOf(provider).IsNil()) {
			return nil, fmt.Errorf("evidence: provider %d is nil", i)
		}
		ref := statement.Policy.Signers[i]
		public, err := provider.ExportPublic(ctx, ref.KeyID)
		if err != nil {
			return nil, fmt.Errorf("evidence: public key %d: %w", i, err)
		}
		if public == nil {
			return nil, fmt.Errorf("evidence: provider returned nil public key")
		}
		actual, err := KeyReference(*public)
		if err != nil || actual != ref {
			return nil, fmt.Errorf("evidence: provider key %d does not match policy", i)
		}
		signature, err := provider.Sign(ctx, ref.KeyID, message, pqc.SignOptions{Context: []byte(SigningContext), Randomized: randomized})
		if err != nil {
			return nil, fmt.Errorf("evidence: signer %d: %w", i, err)
		}
		if signature == nil || !bytes.Equal(signature.Context, []byte(SigningContext)) {
			return nil, fmt.Errorf("evidence: provider returned wrong signing context")
		}
		if err := pqc.VerifyWithPublicKey(*public, message, signature); err != nil {
			return nil, fmt.Errorf("evidence: provider signature %d: %w", i, err)
		}
		result.Signatures = append(result.Signatures, Signature{Signer: i, Value: bytes.Clone(signature.Signature)})
	}
	return result, nil
}

// Verify is strict: every signer pinned by the externally supplied policy must
// verify using trustedKeys in policy order. Now is the verifier's clock, never
// a timestamp copied from the evidence. No unsigned/inspection fallback exists.
func Verify(document *Envelope, payload []byte, expected Policy, trustedKeys []pqc.PublicKey, now time.Time) error {
	if document == nil || document.Schema != Schema {
		return fmt.Errorf("evidence: unsupported or missing schema")
	}
	if err := validatePolicy(expected); err != nil {
		return err
	}
	if !policyEqual(document.Statement.Policy, expected) {
		return fmt.Errorf("evidence: embedded policy does not match trusted policy")
	}
	if now.IsZero() || now.Unix() < expected.NotBefore || now.Unix() >= expected.NotAfter || document.Statement.ClaimedAt > now.Unix() {
		return fmt.Errorf("evidence: policy expired, not active, future claimed time or missing verifier clock")
	}
	message, err := SigningBytes(document.Statement)
	if err != nil {
		return err
	}
	if uint64(len(payload)) != document.Statement.Payload.Length || digest(payload) != document.Statement.Payload.Digest {
		return fmt.Errorf("evidence: payload commitment mismatch")
	}
	if len(document.Signatures) != len(expected.Signers) || len(trustedKeys) != len(expected.Signers) {
		return fmt.Errorf("evidence: all policy signatures and trusted keys are required")
	}
	for i, ref := range expected.Signers {
		actual, err := KeyReference(trustedKeys[i])
		if err != nil || actual != ref {
			return fmt.Errorf("evidence: untrusted/mismatched key at index %d", i)
		}
		signature := document.Signatures[i]
		_, size := sizes(ref.Algorithm)
		if signature.Signer != i || len(signature.Value) != size {
			return fmt.Errorf("evidence: malformed or out-of-order signature %d", i)
		}
		envelope := pqc.SignatureEnvelope{Schema: pqc.SignatureSchema, KeyID: ref.KeyID, KeyVersion: ref.KeyVersion, Algorithm: ref.Algorithm, Context: []byte(SigningContext), Signature: signature.Value}
		if err := pqc.VerifyWithPublicKey(trustedKeys[i], message, &envelope); err != nil {
			return fmt.Errorf("evidence: signature %d: %w", i, err)
		}
	}
	return nil
}
