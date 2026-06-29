package pqc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	MTCLogSchema        = "pqc.mtc-log.v1"
	MTCCheckpointSchema = "pqc.mtc-checkpoint.v1"
	MTCProofSchema      = "pqc.mtc-proof.v1"
)

var mtcCheckpointContext = []byte(MTCCheckpointSchema)

type MTCLog struct {
	Schema    string        `json:"schema"`
	Hash      string        `json:"hash"`
	CreatedAt time.Time     `json:"created_at"`
	Entries   []MTCLogEntry `json:"entries,omitempty"`
}

type MTCLogEntry struct {
	Index                int            `json:"index"`
	Subject              string         `json:"subject"`
	PublicKeyFingerprint string         `json:"public_key_fingerprint"`
	IssuedAt             time.Time      `json:"issued_at"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	LeafHash             string         `json:"leaf_hash"`
}

type MTCCheckpoint struct {
	Schema      string             `json:"schema"`
	Hash        string             `json:"hash"`
	TreeSize    int                `json:"tree_size"`
	MerkleRoot  string             `json:"merkle_root"`
	GeneratedAt time.Time          `json:"generated_at"`
	Signature   *SignatureEnvelope `json:"signature,omitempty"`
}

type MTCProof struct {
	Schema      string         `json:"schema"`
	Hash        string         `json:"hash"`
	LeafIndex   int            `json:"leaf_index"`
	TreeSize    int            `json:"tree_size"`
	Leaf        MTCLogEntry    `json:"leaf"`
	Siblings    []MTCProofNode `json:"siblings,omitempty"`
	MerkleRoot  string         `json:"merkle_root"`
	GeneratedAt time.Time      `json:"generated_at"`
}

type MTCProofNode struct {
	Position string `json:"position"`
	Hash     string `json:"hash"`
}

func NewMTCLog(now time.Time) MTCLog {
	return MTCLog{
		Schema:    MTCLogSchema,
		Hash:      MerkleHashSHA256,
		CreatedAt: mtcTimestamp(now),
	}
}

func (l *MTCLog) Add(subject, publicKeyFingerprint string, metadata map[string]any, now time.Time) (MTCLogEntry, error) {
	if err := l.validate(); err != nil {
		return MTCLogEntry{}, err
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return MTCLogEntry{}, fmt.Errorf("MTC subject is required")
	}
	fingerprint, err := normalizeMTCFingerprint(publicKeyFingerprint)
	if err != nil {
		return MTCLogEntry{}, err
	}
	entry := MTCLogEntry{
		Index:                len(l.Entries),
		Subject:              subject,
		PublicKeyFingerprint: fingerprint,
		IssuedAt:             mtcTimestamp(now),
		Metadata:             cloneMap(metadata),
	}
	leafHash, err := MTCLeafHash(entry)
	if err != nil {
		return MTCLogEntry{}, err
	}
	entry.LeafHash = leafHash
	l.Entries = append(l.Entries, entry)
	return entry, nil
}

func BuildMTCCheckpoint(log MTCLog, now time.Time) (*MTCCheckpoint, error) {
	if err := log.validate(); err != nil {
		return nil, err
	}
	leaves, err := mtcLeafMessages(log.Entries)
	if err != nil {
		return nil, err
	}
	return &MTCCheckpoint{
		Schema:      MTCCheckpointSchema,
		Hash:        MerkleHashSHA256,
		TreeSize:    len(log.Entries),
		MerkleRoot:  MerkleRootHex(leaves),
		GeneratedAt: mtcTimestamp(now),
	}, nil
}

func SignMTCCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *MTCCheckpoint, signKey string) error {
	if err := validateMTCCheckpoint(checkpoint); err != nil {
		return err
	}
	message, err := mtcCheckpointMessage(checkpoint)
	if err != nil {
		return err
	}
	signature, err := manager.Sign(ctx, signKey, message, SignOptions{Context: mtcCheckpointContext})
	if err != nil {
		return err
	}
	checkpoint.Signature = signature
	return nil
}

func BuildMTCProof(log MTCLog, leafIndex int, now time.Time) (*MTCProof, error) {
	if err := log.validate(); err != nil {
		return nil, err
	}
	if leafIndex < 0 || leafIndex >= len(log.Entries) {
		return nil, fmt.Errorf("MTC leaf index %d out of range", leafIndex)
	}
	leafMessages, err := mtcLeafMessages(log.Entries)
	if err != nil {
		return nil, err
	}
	root := hex.EncodeToString(merkleRoot(leafMessages))
	siblings := mtcProofPath(leafMessages, leafIndex)
	return &MTCProof{
		Schema:      MTCProofSchema,
		Hash:        MerkleHashSHA256,
		LeafIndex:   leafIndex,
		TreeSize:    len(log.Entries),
		Leaf:        log.Entries[leafIndex],
		Siblings:    siblings,
		MerkleRoot:  root,
		GeneratedAt: mtcTimestamp(now),
	}, nil
}

func VerifyMTCProof(proof *MTCProof, checkpoint *MTCCheckpoint, publicKey *PublicKey) error {
	if proof == nil {
		return fmt.Errorf("MTC proof is required")
	}
	if checkpoint == nil {
		return fmt.Errorf("MTC checkpoint is required")
	}
	if proof.Schema != MTCProofSchema {
		return fmt.Errorf("unsupported MTC proof schema %q", proof.Schema)
	}
	if checkpoint.Schema != MTCCheckpointSchema {
		return fmt.Errorf("unsupported MTC checkpoint schema %q", checkpoint.Schema)
	}
	if checkpoint.GeneratedAt.IsZero() {
		return fmt.Errorf("MTC checkpoint generated_at is required")
	}
	if proof.GeneratedAt.IsZero() {
		return fmt.Errorf("MTC proof generated_at is required")
	}
	if proof.Hash != MerkleHashSHA256 || checkpoint.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported MTC hash")
	}
	if proof.TreeSize != checkpoint.TreeSize {
		return fmt.Errorf("MTC proof tree size mismatch: got %d want %d", proof.TreeSize, checkpoint.TreeSize)
	}
	if checkpoint.Signature == nil {
		return fmt.Errorf("MTC checkpoint signature is required")
	}
	if publicKey == nil {
		return fmt.Errorf("public key is required to verify MTC checkpoint signature")
	}
	if proof.TreeSize <= 0 {
		return fmt.Errorf("MTC proof tree size must be positive")
	}
	if proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize {
		return fmt.Errorf("MTC proof leaf index %d out of range", proof.LeafIndex)
	}
	if got, want := len(proof.Siblings), merkleProofDepth(proof.TreeSize); got != want {
		return fmt.Errorf("MTC proof sibling count mismatch: got %d want %d", got, want)
	}
	if err := validateMTCNodeHash(proof.MerkleRoot, "MTC proof root"); err != nil {
		return err
	}
	if err := validateMTCNodeHash(checkpoint.MerkleRoot, "MTC checkpoint root"); err != nil {
		return err
	}
	if proof.MerkleRoot != checkpoint.MerkleRoot {
		return fmt.Errorf("MTC proof root mismatch")
	}
	if proof.LeafIndex != proof.Leaf.Index {
		return fmt.Errorf("MTC proof leaf index mismatch")
	}
	if err := validateMTCEntry(proof.Leaf, proof.LeafIndex); err != nil {
		return err
	}
	actualRoot, err := mtcRootFromProof(proof)
	if err != nil {
		return err
	}
	if actualRoot != checkpoint.MerkleRoot {
		return fmt.Errorf("MTC proof does not resolve to checkpoint root")
	}
	message, err := mtcCheckpointMessage(checkpoint)
	if err != nil {
		return err
	}
	if err := VerifyWithPublicKey(*publicKey, message, checkpoint.Signature); err != nil {
		return err
	}
	return nil
}

func MTCLeafHash(entry MTCLogEntry) (string, error) {
	message, err := mtcLeafMessage(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("pqc.merkle.leaf.v1:"), message...))
	return hex.EncodeToString(sum[:]), nil
}

func (l MTCLog) validate() error {
	if l.Schema != MTCLogSchema {
		return fmt.Errorf("unsupported MTC log schema %q", l.Schema)
	}
	if l.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported MTC log hash %q", l.Hash)
	}
	if l.CreatedAt.IsZero() {
		return fmt.Errorf("MTC log created_at is required")
	}
	for i, entry := range l.Entries {
		if err := validateMTCEntry(entry, i); err != nil {
			return err
		}
	}
	return nil
}

func validateMTCEntry(entry MTCLogEntry, expectedIndex int) error {
	if entry.Index != expectedIndex {
		return fmt.Errorf("MTC log entry index mismatch at %d", expectedIndex)
	}
	if strings.TrimSpace(entry.Subject) == "" {
		return fmt.Errorf("MTC log entry %d subject is required", expectedIndex)
	}
	if entry.Subject != strings.TrimSpace(entry.Subject) {
		return fmt.Errorf("MTC log entry %d subject is not canonical", expectedIndex)
	}
	fingerprint, err := normalizeMTCFingerprint(entry.PublicKeyFingerprint)
	if err != nil {
		return fmt.Errorf("MTC log entry %d: %w", expectedIndex, err)
	}
	if entry.PublicKeyFingerprint != fingerprint {
		return fmt.Errorf("MTC log entry %d public key fingerprint is not canonical", expectedIndex)
	}
	if entry.IssuedAt.IsZero() {
		return fmt.Errorf("MTC log entry %d issued_at is required", expectedIndex)
	}
	if err := validateMTCNodeHash(entry.LeafHash, fmt.Sprintf("MTC log entry %d leaf hash", expectedIndex)); err != nil {
		return err
	}
	leafHash, err := MTCLeafHash(entry)
	if err != nil {
		return err
	}
	if entry.LeafHash != leafHash {
		return fmt.Errorf("MTC log entry %d leaf hash mismatch", expectedIndex)
	}
	return nil
}

func mtcLeafMessages(entries []MTCLogEntry) ([][]byte, error) {
	leaves := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		message, err := mtcLeafMessage(entry)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, message)
	}
	return leaves, nil
}

func mtcLeafMessage(entry MTCLogEntry) ([]byte, error) {
	return json.Marshal(struct {
		Index                int            `json:"index"`
		Subject              string         `json:"subject"`
		PublicKeyFingerprint string         `json:"public_key_fingerprint"`
		IssuedAt             time.Time      `json:"issued_at"`
		Metadata             map[string]any `json:"metadata,omitempty"`
	}{
		Index:                entry.Index,
		Subject:              entry.Subject,
		PublicKeyFingerprint: entry.PublicKeyFingerprint,
		IssuedAt:             entry.IssuedAt.UTC(),
		Metadata:             entry.Metadata,
	})
}

func mtcCheckpointMessage(checkpoint *MTCCheckpoint) ([]byte, error) {
	if err := validateMTCCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Schema      string    `json:"schema"`
		Hash        string    `json:"hash"`
		TreeSize    int       `json:"tree_size"`
		MerkleRoot  string    `json:"merkle_root"`
		GeneratedAt time.Time `json:"generated_at"`
	}{
		Schema:      checkpoint.Schema,
		Hash:        checkpoint.Hash,
		TreeSize:    checkpoint.TreeSize,
		MerkleRoot:  checkpoint.MerkleRoot,
		GeneratedAt: checkpoint.GeneratedAt.UTC(),
	})
}

func validateMTCCheckpoint(checkpoint *MTCCheckpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("MTC checkpoint is required")
	}
	if checkpoint.Schema != MTCCheckpointSchema {
		return fmt.Errorf("unsupported MTC checkpoint schema %q", checkpoint.Schema)
	}
	if checkpoint.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported MTC checkpoint hash %q", checkpoint.Hash)
	}
	if checkpoint.TreeSize < 0 {
		return fmt.Errorf("MTC checkpoint tree size must be non-negative")
	}
	if err := validateMTCNodeHash(checkpoint.MerkleRoot, "MTC checkpoint root"); err != nil {
		return err
	}
	if checkpoint.GeneratedAt.IsZero() {
		return fmt.Errorf("MTC checkpoint generated_at is required")
	}
	return nil
}

func mtcProofPath(leafMessages [][]byte, index int) []MTCProofNode {
	level := merkleLeafHashes(leafMessages)
	path := []MTCProofNode{}
	for len(level) > 1 {
		siblingIndex := index ^ 1
		position := "right"
		if siblingIndex < index {
			position = "left"
		}
		if siblingIndex >= len(level) {
			siblingIndex = index
		}
		path = append(path, MTCProofNode{
			Position: position,
			Hash:     hex.EncodeToString(level[siblingIndex]),
		})
		index /= 2
		level = merkleParentLevel(level)
	}
	return path
}

func merkleProofDepth(size int) int {
	depth := 0
	for size > 1 {
		depth++
		size = (size + 1) / 2
	}
	return depth
}

func mtcRootFromProof(proof *MTCProof) (string, error) {
	leafMessage, err := mtcLeafMessage(proof.Leaf)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("pqc.merkle.leaf.v1:"), leafMessage...))
	current := sum[:]
	for _, sibling := range proof.Siblings {
		decoded, err := decodeMTCNodeHash(sibling.Hash, "MTC proof sibling hash")
		if err != nil {
			return "", err
		}
		switch sibling.Position {
		case "left":
			current = merkleParent(decoded, current)
		case "right":
			current = merkleParent(current, decoded)
		default:
			return "", fmt.Errorf("invalid MTC proof sibling position %q", sibling.Position)
		}
	}
	return hex.EncodeToString(current), nil
}

func normalizeMTCFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("MTC public key fingerprint is required")
	}
	if strings.HasPrefix(strings.ToLower(value), "sha256:") {
		value = "sha256:" + strings.TrimSpace(value[len("sha256:"):])
	} else {
		value = "sha256:" + value
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != sha256.Size*2 {
		return "", fmt.Errorf("MTC public key fingerprint must be sha256:HEX")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", fmt.Errorf("MTC public key fingerprint must be sha256:HEX")
	}
	return "sha256:" + strings.ToLower(hexPart), nil
}

func validateMTCNodeHash(value, label string) error {
	_, err := decodeMTCNodeHash(value, label)
	return err
}

func decodeMTCNodeHash(value, label string) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, fmt.Errorf("%s must be %d hex characters", label, sha256.Size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", label, err)
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%s must decode to %d bytes", label, sha256.Size)
	}
	return decoded, nil
}

func mtcTimestamp(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func merkleLeafHashes(leaves [][]byte) [][]byte {
	level := make([][]byte, 0, len(leaves))
	for _, leaf := range leaves {
		sum := sha256.Sum256(append([]byte("pqc.merkle.leaf.v1:"), leaf...))
		level = append(level, sum[:])
	}
	return level
}

func merkleParentLevel(level [][]byte) [][]byte {
	next := make([][]byte, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		left := level[i]
		right := left
		if i+1 < len(level) {
			right = level[i+1]
		}
		next = append(next, merkleParent(left, right))
	}
	return next
}

func merkleParent(left, right []byte) []byte {
	buf := make([]byte, 0, len("pqc.merkle.node.v1:")+len(left)+len(right))
	buf = append(buf, []byte("pqc.merkle.node.v1:")...)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
