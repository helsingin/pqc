// Package evidence implements policy-bound, public-only verification of v2
// evidence. It does not change the interpretation of existing pqc v1 formats.
package evidence

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/helsingin/pqc"
)

const (
	Schema           = "pqc.evidence.v2"
	PolicySchema     = "pqc.evidence-policy.v1"
	Hash             = "SHA-512"
	SigningContext   = Schema
	MaxDocumentBytes = 1 << 20
	maxTime          = 253402300799
)

type SignerRef struct {
	KeyID           string        `json:"key_id"`
	KeyVersion      int           `json:"key_version"`
	Algorithm       pqc.Algorithm `json:"algorithm"`
	PublicKeyDigest string        `json:"public_key_digest"`
}
type Policy struct {
	Schema    string      `json:"schema"`
	ID        string      `json:"id"`
	Version   int         `json:"version"`
	Purpose   string      `json:"purpose"`
	Context   string      `json:"context"`
	NotBefore int64       `json:"not_before"`
	NotAfter  int64       `json:"not_after"`
	Signers   []SignerRef `json:"signers"`
}
type Payload struct {
	Hash      string `json:"hash"`
	Digest    string `json:"digest"`
	Length    uint64 `json:"length"`
	MediaType string `json:"media_type"`
}
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type Statement struct {
	Policy    Policy  `json:"policy"`
	Payload   Payload `json:"payload"`
	ClaimedAt int64   `json:"claimed_at"`
	Metadata  []Field `json:"metadata"`
}
type Signature struct {
	Signer int    `json:"signer"`
	Value  []byte `json:"value"`
}
type Envelope struct {
	Schema     string      `json:"schema"`
	Statement  Statement   `json:"statement"`
	Signatures []Signature `json:"signatures"`
}

func digest(data []byte) string { sum := sha512.Sum512(data); return hex.EncodeToString(sum[:]) }

func sizes(algorithm pqc.Algorithm) (public, signature int) {
	switch algorithm {
	case pqc.AlgorithmMLDSA65:
		return 1952, 3309
	case pqc.AlgorithmMLDSA87:
		return 2592, 4627
	case pqc.AlgorithmSLHDSASHA2192s:
		return 48, 16224
	case pqc.AlgorithmSLHDSASHA2256s:
		return 64, 29792
	default:
		return 0, 0
	}
}

// KeyReference binds exact public bytes and metadata; it does not establish trust.
func KeyReference(key pqc.PublicKey) (SignerRef, error) {
	size, _ := sizes(key.Algorithm)
	if size == 0 || len(key.PublicKey) != size || key.Use != pqc.KeyUseSignature {
		return SignerRef{}, fmt.Errorf("evidence: invalid signing public key")
	}
	ref := SignerRef{key.ID, key.Version, key.Algorithm, digest(key.PublicKey)}
	if err := validateRef(ref); err != nil {
		return SignerRef{}, err
	}
	return ref, nil
}

// NewStatement commits to the exact payload bytes. ClaimedAt is a signed claim,
// never a trusted timestamp. Metadata order is insignificant; keys are unique.
func NewStatement(policy Policy, payload []byte, mediaType string, claimedAt time.Time, metadata []Field) (Statement, error) {
	statement := Statement{Policy: policy, Payload: Payload{Hash: Hash, Digest: digest(payload), Length: uint64(len(payload)), MediaType: mediaType}, ClaimedAt: claimedAt.Unix(), Metadata: append([]Field{}, metadata...)}
	statement.Policy.Signers = append([]SignerRef(nil), policy.Signers...)
	sort.Slice(statement.Metadata, func(i, j int) bool { return statement.Metadata[i].Key < statement.Metadata[j].Key })
	if claimedAt.IsZero() {
		return Statement{}, fmt.Errorf("evidence: claimed time is required")
	}
	if err := validateStatement(statement); err != nil {
		return Statement{}, err
	}
	return statement, nil
}

func textOK(value string, limit int, empty bool) bool {
	return utf8.ValidString(value) && len(value) <= limit && (empty || value != "")
}
func digestOK(value string) bool {
	if len(value) != 128 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validateRef(ref SignerRef) error {
	public, _ := sizes(ref.Algorithm)
	if !textOK(ref.KeyID, 1024, false) || ref.KeyVersion < 1 || ref.KeyVersion > math.MaxInt32 || public == 0 || !digestOK(ref.PublicKeyDigest) {
		return fmt.Errorf("evidence: invalid signer reference")
	}
	return nil
}
func validatePolicy(policy Policy) error {
	if policy.Schema != PolicySchema || !textOK(policy.ID, 1024, false) || policy.Version < 1 || policy.Version > math.MaxInt32 {
		return fmt.Errorf("evidence: invalid policy identity/version")
	}
	if !textOK(policy.Purpose, 1024, false) || !textOK(policy.Context, 1024, true) {
		return fmt.Errorf("evidence: invalid purpose/context")
	}
	if policy.NotBefore < 0 || policy.NotAfter > maxTime || policy.NotAfter <= policy.NotBefore {
		return fmt.Errorf("evidence: invalid policy interval")
	}
	if len(policy.Signers) < 1 || len(policy.Signers) > 8 {
		return fmt.Errorf("evidence: policy requires 1 to 8 signers")
	}
	identities := map[string]bool{}
	materials := map[string]bool{}
	for _, ref := range policy.Signers {
		if err := validateRef(ref); err != nil {
			return err
		}
		identity := fmt.Sprintf("%d:%s:%d", len(ref.KeyID), ref.KeyID, ref.KeyVersion)
		if identities[identity] || materials[ref.PublicKeyDigest] {
			return fmt.Errorf("evidence: duplicate signer identity or key material")
		}
		identities[identity] = true
		materials[ref.PublicKeyDigest] = true
	}
	return nil
}
func validateStatement(statement Statement) error {
	if err := validatePolicy(statement.Policy); err != nil {
		return err
	}
	if statement.Payload.Hash != Hash || !digestOK(statement.Payload.Digest) || statement.Payload.Length > 1<<53-1 || !textOK(statement.Payload.MediaType, 1024, false) {
		return fmt.Errorf("evidence: invalid payload commitment")
	}
	if statement.ClaimedAt < statement.Policy.NotBefore || statement.ClaimedAt >= statement.Policy.NotAfter {
		return fmt.Errorf("evidence: claimed time outside policy interval")
	}
	if len(statement.Metadata) > 64 {
		return fmt.Errorf("evidence: too many metadata fields")
	}
	seen := map[string]bool{}
	for _, field := range statement.Metadata {
		if !textOK(field.Key, 256, false) || !textOK(field.Value, 4096, true) || seen[field.Key] {
			return fmt.Errorf("evidence: invalid or duplicate metadata key")
		}
		seen[field.Key] = true
	}
	return nil
}
