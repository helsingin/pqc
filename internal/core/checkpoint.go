package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	MerkleHashSHA256             = "SHA-256"
	AuditCheckpointSchema        = "pqc.audit-checkpoint.v1"
	InventoryReportSchema        = "pqc.inventory.v1"
	TransparencyCheckpointSchema = "pqc.transparency-checkpoint.v1"
	TransparencyBundleSchema     = "pqc.transparency-bundle.v1"
)

var (
	auditCheckpointContext        = []byte("pqc.audit-checkpoint.v1")
	transparencyCheckpointContext = []byte("pqc.transparency-checkpoint.v1")
)

type AuditCheckpoint struct {
	Schema      string             `json:"schema"`
	Hash        string             `json:"hash"`
	LeafCount   int                `json:"leaf_count"`
	MerkleRoot  string             `json:"merkle_root"`
	AuditDigest string             `json:"audit_digest"`
	CreatedAt   time.Time          `json:"created_at"`
	Signature   *SignatureEnvelope `json:"signature,omitempty"`
}

type InventoryEntry struct {
	ID                   string    `json:"id"`
	Algorithm            Algorithm `json:"algorithm"`
	Use                  KeyUse    `json:"use"`
	Version              int       `json:"version"`
	CreatedAt            time.Time `json:"created_at"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	RotationAgeHours     int       `json:"rotation_age_hours"`
}

type InventoryReport struct {
	Schema          string           `json:"schema"`
	CreatedAt       time.Time        `json:"created_at"`
	Policy          string           `json:"policy,omitempty"`
	KeyStoreScanned bool             `json:"key_store_scanned,omitempty"`
	Keys            []InventoryEntry `json:"keys,omitempty"`
	Targets         []TLSReport      `json:"targets,omitempty"`
	Warnings        []string         `json:"warnings,omitempty"`
}

type TransparencyCheckpoint struct {
	Schema           string             `json:"schema"`
	Hash             string             `json:"hash"`
	GeneratedAt      time.Time          `json:"generated_at"`
	KeyCount         int                `json:"key_count"`
	TargetCount      int                `json:"target_count"`
	RevocationCount  int                `json:"revocation_count"`
	MerkleRoot       string             `json:"merkle_root"`
	InventoryRoot    string             `json:"inventory_root"`
	RevocationRoot   string             `json:"revocation_root,omitempty"`
	RevocationDigest string             `json:"revocation_digest,omitempty"`
	Signature        *SignatureEnvelope `json:"signature,omitempty"`
}

type TransparencyBundle struct {
	Schema      string                 `json:"schema"`
	Inventory   InventoryReport        `json:"inventory"`
	Revocations *RevocationManifest    `json:"revocations,omitempty"`
	Checkpoint  TransparencyCheckpoint `json:"checkpoint"`
}

func BuildAuditCheckpoint(r io.Reader, now time.Time) (*AuditCheckpoint, error) {
	lines, digest, err := readNonEmptyLines(r)
	if err != nil {
		return nil, err
	}
	root := MerkleRootHex(lines)
	return &AuditCheckpoint{
		Schema:      AuditCheckpointSchema,
		Hash:        MerkleHashSHA256,
		LeafCount:   len(lines),
		MerkleRoot:  root,
		AuditDigest: digest,
		CreatedAt:   now.UTC(),
	}, nil
}

func SignAuditCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *AuditCheckpoint, signKey string) error {
	message, err := auditCheckpointMessage(checkpoint)
	if err != nil {
		return err
	}
	signature, err := manager.Sign(ctx, signKey, message, SignOptions{Context: auditCheckpointContext})
	if err != nil {
		return err
	}
	checkpoint.Signature = signature
	return nil
}

func VerifyAuditCheckpoint(r io.Reader, checkpoint *AuditCheckpoint, publicKey *PublicKey) error {
	if checkpoint == nil {
		return fmt.Errorf("audit checkpoint is required")
	}
	actual, err := BuildAuditCheckpoint(r, checkpoint.CreatedAt)
	if err != nil {
		return err
	}
	if checkpoint.Schema != AuditCheckpointSchema {
		return fmt.Errorf("unsupported audit checkpoint schema %q", checkpoint.Schema)
	}
	if checkpoint.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported audit checkpoint hash %q", checkpoint.Hash)
	}
	if checkpoint.LeafCount != actual.LeafCount {
		return fmt.Errorf("audit checkpoint leaf count mismatch: got %d want %d", actual.LeafCount, checkpoint.LeafCount)
	}
	if checkpoint.MerkleRoot != actual.MerkleRoot {
		return fmt.Errorf("audit checkpoint Merkle root mismatch")
	}
	if checkpoint.AuditDigest != actual.AuditDigest {
		return fmt.Errorf("audit checkpoint digest mismatch")
	}
	if checkpoint.Signature != nil {
		if publicKey == nil {
			return fmt.Errorf("public key is required to verify checkpoint signature")
		}
		message, err := auditCheckpointMessage(checkpoint)
		if err != nil {
			return err
		}
		if err := VerifyWithPublicKey(*publicKey, message, checkpoint.Signature); err != nil {
			return err
		}
	}
	return nil
}

func BuildInventoryReport(keys []KeyMetadata, targets []TLSReport, now time.Time) InventoryReport {
	report := InventoryReport{
		Schema:          InventoryReportSchema,
		CreatedAt:       now.UTC(),
		KeyStoreScanned: keys != nil,
		Targets:         append([]TLSReport(nil), targets...),
	}
	for _, key := range keys {
		entry := InventoryEntry{
			ID:                   key.ID,
			Algorithm:            key.Algorithm,
			Use:                  key.Use,
			Version:              key.Version,
			CreatedAt:            key.CreatedAt.UTC(),
			PublicKeyFingerprint: PublicKeyFingerprint(key.PublicKey),
		}
		if !key.CreatedAt.IsZero() {
			entry.RotationAgeHours = int(now.UTC().Sub(key.CreatedAt.UTC()).Hours())
		}
		report.Keys = append(report.Keys, entry)
	}
	sort.Slice(report.Keys, func(i, j int) bool {
		if report.Keys[i].ID == report.Keys[j].ID {
			return report.Keys[i].Version < report.Keys[j].Version
		}
		return report.Keys[i].ID < report.Keys[j].ID
	})
	sort.Slice(report.Targets, func(i, j int) bool {
		return report.Targets[i].Target < report.Targets[j].Target
	})
	return report
}

func BuildTransparencyCheckpoint(report InventoryReport, now time.Time) (*TransparencyCheckpoint, error) {
	return BuildTransparencyCheckpointWithRevocations(report, nil, now)
}

func BuildTransparencyCheckpointWithRevocations(report InventoryReport, revocations *RevocationManifest, now time.Time) (*TransparencyCheckpoint, error) {
	inventoryLeaves, err := inventoryLeaves(report)
	if err != nil {
		return nil, err
	}
	inventoryRoot := MerkleRootHex(inventoryLeaves)
	allLeaves := append([][]byte(nil), inventoryLeaves...)
	checkpoint := &TransparencyCheckpoint{
		Schema:        TransparencyCheckpointSchema,
		Hash:          MerkleHashSHA256,
		GeneratedAt:   mtcTimestamp(now),
		KeyCount:      len(report.Keys),
		TargetCount:   len(report.Targets),
		InventoryRoot: inventoryRoot,
	}
	if revocations != nil {
		if err := revocations.validate(); err != nil {
			return nil, err
		}
		revLeaves, err := revocationLeaves(*revocations)
		if err != nil {
			return nil, err
		}
		checkpoint.RevocationCount = len(revocations.Events)
		checkpoint.RevocationRoot = MerkleRootHex(revLeaves)
		digest, err := RevocationManifestDigest(*revocations)
		if err != nil {
			return nil, err
		}
		checkpoint.RevocationDigest = digest
		for _, leaf := range revLeaves {
			data, err := json.Marshal(struct {
				Type  string `json:"type"`
				Value []byte `json:"value"`
			}{Type: "revocation", Value: leaf})
			if err != nil {
				return nil, err
			}
			allLeaves = append(allLeaves, data)
		}
	}
	sort.Slice(allLeaves, func(i, j int) bool {
		return bytes.Compare(allLeaves[i], allLeaves[j]) < 0
	})
	checkpoint.MerkleRoot = MerkleRootHex(allLeaves)
	return checkpoint, nil
}

func SignTransparencyCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *TransparencyCheckpoint, signKey string) error {
	message, err := transparencyCheckpointMessage(checkpoint)
	if err != nil {
		return err
	}
	signature, err := manager.Sign(ctx, signKey, message, SignOptions{Context: transparencyCheckpointContext})
	if err != nil {
		return err
	}
	checkpoint.Signature = signature
	return nil
}

func VerifyTransparencyCheckpoint(report InventoryReport, checkpoint *TransparencyCheckpoint, publicKey *PublicKey) error {
	return VerifyTransparencyCheckpointWithRevocations(report, nil, checkpoint, publicKey)
}

func VerifyTransparencyCheckpointWithRevocations(report InventoryReport, revocations *RevocationManifest, checkpoint *TransparencyCheckpoint, publicKey *PublicKey) error {
	if checkpoint == nil {
		return fmt.Errorf("transparency checkpoint is required")
	}
	if checkpoint.GeneratedAt.IsZero() {
		return fmt.Errorf("transparency checkpoint generated_at is required")
	}
	actual, err := BuildTransparencyCheckpointWithRevocations(report, revocations, checkpoint.GeneratedAt)
	if err != nil {
		return err
	}
	if checkpoint.Schema != TransparencyCheckpointSchema {
		return fmt.Errorf("unsupported transparency checkpoint schema %q", checkpoint.Schema)
	}
	if checkpoint.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported transparency checkpoint hash %q", checkpoint.Hash)
	}
	if checkpoint.KeyCount != actual.KeyCount {
		return fmt.Errorf("transparency checkpoint key count mismatch: got %d want %d", actual.KeyCount, checkpoint.KeyCount)
	}
	if checkpoint.TargetCount != actual.TargetCount {
		return fmt.Errorf("transparency checkpoint target count mismatch: got %d want %d", actual.TargetCount, checkpoint.TargetCount)
	}
	if !checkpoint.GeneratedAt.Equal(actual.GeneratedAt) {
		return fmt.Errorf("transparency checkpoint generated_at mismatch")
	}
	if checkpoint.RevocationCount != actual.RevocationCount {
		return fmt.Errorf("transparency checkpoint revocation count mismatch: got %d want %d", actual.RevocationCount, checkpoint.RevocationCount)
	}
	if checkpoint.MerkleRoot != actual.MerkleRoot ||
		checkpoint.InventoryRoot != actual.InventoryRoot ||
		checkpoint.RevocationRoot != actual.RevocationRoot ||
		checkpoint.RevocationDigest != actual.RevocationDigest {
		return fmt.Errorf("transparency checkpoint root mismatch")
	}
	if checkpoint.Signature != nil {
		if publicKey == nil {
			return fmt.Errorf("public key is required to verify checkpoint signature")
		}
		message, err := transparencyCheckpointMessage(checkpoint)
		if err != nil {
			return err
		}
		if err := VerifyWithPublicKey(*publicKey, message, checkpoint.Signature); err != nil {
			return err
		}
	}
	return nil
}

func BuildTransparencyBundle(report InventoryReport, checkpoint *TransparencyCheckpoint) (TransparencyBundle, error) {
	return BuildTransparencyBundleWithRevocations(report, nil, checkpoint)
}

func BuildTransparencyBundleWithRevocations(report InventoryReport, revocations *RevocationManifest, checkpoint *TransparencyCheckpoint) (TransparencyBundle, error) {
	if checkpoint == nil {
		return TransparencyBundle{}, fmt.Errorf("transparency checkpoint is required")
	}
	actual, err := BuildTransparencyCheckpointWithRevocations(report, revocations, checkpoint.GeneratedAt)
	if err != nil {
		return TransparencyBundle{}, err
	}
	if checkpoint.Schema != actual.Schema ||
		checkpoint.Hash != actual.Hash ||
		!checkpoint.GeneratedAt.Equal(actual.GeneratedAt) ||
		checkpoint.KeyCount != actual.KeyCount ||
		checkpoint.TargetCount != actual.TargetCount ||
		checkpoint.RevocationCount != actual.RevocationCount ||
		checkpoint.MerkleRoot != actual.MerkleRoot ||
		checkpoint.InventoryRoot != actual.InventoryRoot ||
		checkpoint.RevocationRoot != actual.RevocationRoot ||
		checkpoint.RevocationDigest != actual.RevocationDigest {
		return TransparencyBundle{}, fmt.Errorf("transparency checkpoint does not match bundle contents")
	}
	bundle := TransparencyBundle{
		Schema:     TransparencyBundleSchema,
		Inventory:  report,
		Checkpoint: *checkpoint,
	}
	if revocations != nil {
		copy := *revocations
		copy.Events = append([]RevocationEvent(nil), revocations.Events...)
		bundle.Revocations = &copy
	}
	return bundle, nil
}

func VerifyTransparencyBundle(bundle TransparencyBundle, publicKey *PublicKey) error {
	if bundle.Schema != TransparencyBundleSchema {
		return fmt.Errorf("unsupported transparency bundle schema %q", bundle.Schema)
	}
	return VerifyTransparencyCheckpointWithRevocations(bundle.Inventory, bundle.Revocations, &bundle.Checkpoint, publicKey)
}

func PublicKeyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func MerkleRootHex(leaves [][]byte) string {
	root := merkleRoot(leaves)
	return hex.EncodeToString(root)
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		sum := sha256.Sum256([]byte("pqc.merkle.empty.v1"))
		return sum[:]
	}
	level := make([][]byte, 0, len(leaves))
	for _, leaf := range leaves {
		sum := sha256.Sum256(append([]byte("pqc.merkle.leaf.v1:"), leaf...))
		level = append(level, sum[:])
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			buf := make([]byte, 0, len("pqc.merkle.node.v1:")+len(left)+len(right))
			buf = append(buf, []byte("pqc.merkle.node.v1:")...)
			buf = append(buf, left...)
			buf = append(buf, right...)
			sum := sha256.Sum256(buf)
			next = append(next, sum[:])
		}
		level = next
	}
	return level[0]
}

func readNonEmptyLines(r io.Reader) ([][]byte, string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var lines [][]byte
	digest := sha256.New()
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			continue
		}
		copied := append([]byte(nil), line...)
		lines = append(lines, copied)
		digest.Write(copied)
		digest.Write([]byte{'\n'})
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return lines, "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func inventoryLeaves(report InventoryReport) ([][]byte, error) {
	var leaves [][]byte
	for _, key := range report.Keys {
		data, err := json.Marshal(struct {
			Type  string         `json:"type"`
			Value InventoryEntry `json:"value"`
		}{Type: "key", Value: key})
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, data)
	}
	for _, target := range report.Targets {
		data, err := json.Marshal(struct {
			Type  string    `json:"type"`
			Value TLSReport `json:"value"`
		}{Type: "target", Value: target})
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, data)
	}
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i], leaves[j]) < 0
	})
	return leaves, nil
}

func auditCheckpointMessage(checkpoint *AuditCheckpoint) ([]byte, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("audit checkpoint is required")
	}
	return json.Marshal(struct {
		Schema      string    `json:"schema"`
		Hash        string    `json:"hash"`
		LeafCount   int       `json:"leaf_count"`
		MerkleRoot  string    `json:"merkle_root"`
		AuditDigest string    `json:"audit_digest"`
		CreatedAt   time.Time `json:"created_at"`
	}{
		Schema:      checkpoint.Schema,
		Hash:        checkpoint.Hash,
		LeafCount:   checkpoint.LeafCount,
		MerkleRoot:  checkpoint.MerkleRoot,
		AuditDigest: checkpoint.AuditDigest,
		CreatedAt:   checkpoint.CreatedAt.UTC(),
	})
}

func transparencyCheckpointMessage(checkpoint *TransparencyCheckpoint) ([]byte, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("transparency checkpoint is required")
	}
	return json.Marshal(struct {
		Schema           string    `json:"schema"`
		Hash             string    `json:"hash"`
		GeneratedAt      time.Time `json:"generated_at"`
		KeyCount         int       `json:"key_count"`
		TargetCount      int       `json:"target_count"`
		RevocationCount  int       `json:"revocation_count"`
		MerkleRoot       string    `json:"merkle_root"`
		InventoryRoot    string    `json:"inventory_root"`
		RevocationRoot   string    `json:"revocation_root,omitempty"`
		RevocationDigest string    `json:"revocation_digest,omitempty"`
	}{
		Schema:           checkpoint.Schema,
		Hash:             checkpoint.Hash,
		GeneratedAt:      checkpoint.GeneratedAt.UTC(),
		KeyCount:         checkpoint.KeyCount,
		TargetCount:      checkpoint.TargetCount,
		RevocationCount:  checkpoint.RevocationCount,
		MerkleRoot:       checkpoint.MerkleRoot,
		InventoryRoot:    checkpoint.InventoryRoot,
		RevocationRoot:   checkpoint.RevocationRoot,
		RevocationDigest: checkpoint.RevocationDigest,
	})
}
