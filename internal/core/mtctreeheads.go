package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	MTCTreeheadCacheSchema = "pqc.mtc-treehead-cache.v1"
)

type MTCTreeheadCache struct {
	Schema    string             `json:"schema"`
	Source    string             `json:"source,omitempty"`
	FetchedAt time.Time          `json:"fetched_at"`
	Treeheads []MTCTreeheadEntry `json:"treeheads"`
}

type MTCTreeheadEntry struct {
	ID         string        `json:"id"`
	LogID      string        `json:"log_id"`
	Source     string        `json:"source,omitempty"`
	Checkpoint MTCCheckpoint `json:"checkpoint"`
	PublicKey  PublicKey     `json:"public_key"`
	ReceivedAt time.Time     `json:"received_at"`
}

type MTCTreeheadVerifyResult struct {
	OK       bool                 `json:"ok"`
	Verified int                  `json:"verified"`
	Findings []MTCTreeheadFinding `json:"findings,omitempty"`
}

type MTCTreeheadFinding struct {
	Severity string         `json:"severity"`
	Subject  string         `json:"subject"`
	Message  string         `json:"message"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

func NewMTCTreeheadCache(source string, entries []MTCTreeheadEntry, now time.Time) MTCTreeheadCache {
	cache := MTCTreeheadCache{
		Schema:    MTCTreeheadCacheSchema,
		Source:    strings.TrimSpace(source),
		FetchedAt: mtcTimestamp(now),
		Treeheads: append([]MTCTreeheadEntry(nil), entries...),
	}
	sort.Slice(cache.Treeheads, func(i, j int) bool {
		if cache.Treeheads[i].LogID == cache.Treeheads[j].LogID {
			if cache.Treeheads[i].Checkpoint.TreeSize == cache.Treeheads[j].Checkpoint.TreeSize {
				return cache.Treeheads[i].ID < cache.Treeheads[j].ID
			}
			return cache.Treeheads[i].Checkpoint.TreeSize < cache.Treeheads[j].Checkpoint.TreeSize
		}
		return cache.Treeheads[i].LogID < cache.Treeheads[j].LogID
	})
	return cache
}

func NewMTCTreeheadEntry(source, logID string, checkpoint MTCCheckpoint, publicKey PublicKey, now time.Time) (MTCTreeheadEntry, error) {
	source = strings.TrimSpace(source)
	logID = strings.TrimSpace(logID)
	if logID == "" {
		logID = DefaultMTCTreeheadLogID(source)
	}
	if logID == "" {
		return MTCTreeheadEntry{}, fmt.Errorf("MTC treehead log id is required")
	}
	if checkpoint.Signature == nil {
		return MTCTreeheadEntry{}, fmt.Errorf("MTC treehead checkpoint signature is required")
	}
	message, err := mtcCheckpointMessage(&checkpoint)
	if err != nil {
		return MTCTreeheadEntry{}, err
	}
	if err := VerifyWithPublicKey(publicKey, message, checkpoint.Signature); err != nil {
		return MTCTreeheadEntry{}, err
	}
	entry := MTCTreeheadEntry{
		LogID:      logID,
		Source:     source,
		Checkpoint: checkpoint,
		PublicKey:  publicKey,
		ReceivedAt: mtcTimestamp(now),
	}
	id, err := MTCTreeheadEntryID(entry)
	if err != nil {
		return MTCTreeheadEntry{}, err
	}
	entry.ID = id
	return entry, nil
}

func MTCTreeheadEntryID(entry MTCTreeheadEntry) (string, error) {
	if strings.TrimSpace(entry.LogID) == "" {
		return "", fmt.Errorf("MTC treehead log id is required")
	}
	if err := validateMTCCheckpoint(&entry.Checkpoint); err != nil {
		return "", err
	}
	if entry.Checkpoint.Signature == nil {
		return "", fmt.Errorf("MTC treehead checkpoint signature is required")
	}
	data, err := json.Marshal(struct {
		LogID               string    `json:"log_id"`
		TreeSize            int       `json:"tree_size"`
		MerkleRoot          string    `json:"merkle_root"`
		GeneratedAt         time.Time `json:"generated_at"`
		SignerKeyID         string    `json:"signer_key_id"`
		SignerVersion       int       `json:"signer_version"`
		SignerAlgorithm     Algorithm `json:"signer_algorithm"`
		SignerPublicKeyHash string    `json:"signer_public_key_hash"`
		SignatureSchema     string    `json:"signature_schema"`
		SignatureContext    string    `json:"signature_context"`
		SignatureValue      string    `json:"signature_value"`
	}{
		LogID:               strings.TrimSpace(entry.LogID),
		TreeSize:            entry.Checkpoint.TreeSize,
		MerkleRoot:          entry.Checkpoint.MerkleRoot,
		GeneratedAt:         entry.Checkpoint.GeneratedAt.UTC(),
		SignerKeyID:         entry.Checkpoint.Signature.KeyID,
		SignerVersion:       entry.Checkpoint.Signature.KeyVersion,
		SignerAlgorithm:     entry.Checkpoint.Signature.Algorithm,
		SignerPublicKeyHash: PublicKeyFingerprint(entry.PublicKey.PublicKey),
		SignatureSchema:     entry.Checkpoint.Signature.Schema,
		SignatureContext:    hex.EncodeToString(entry.Checkpoint.Signature.Context),
		SignatureValue:      hex.EncodeToString(entry.Checkpoint.Signature.Signature),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func VerifyMTCTreeheadCache(cache MTCTreeheadCache) (*MTCTreeheadVerifyResult, error) {
	result := &MTCTreeheadVerifyResult{OK: true}
	if cache.Schema != MTCTreeheadCacheSchema {
		result.OK = false
		result.Findings = append(result.Findings, mtcTreeheadFinding("error", "schema", "unsupported MTC treehead cache schema", map[string]any{
			"schema": cache.Schema,
		}))
		return result, fmt.Errorf("unsupported MTC treehead cache schema %q", cache.Schema)
	}
	if cache.FetchedAt.IsZero() {
		result.OK = false
		result.Findings = append(result.Findings, mtcTreeheadFinding("error", "fetched_at", "MTC treehead cache fetched_at is required", nil))
	}
	if len(cache.Treeheads) == 0 {
		result.OK = false
		result.Findings = append(result.Findings, mtcTreeheadFinding("error", "treeheads", "MTC treehead cache is empty", nil))
	}

	ids := map[string]bool{}
	rootsByLogAndSize := map[string]string{}
	byLog := map[string][]MTCTreeheadEntry{}
	for i, entry := range cache.Treeheads {
		subject := fmt.Sprintf("treeheads[%d]", i)
		if entry.ReceivedAt.IsZero() {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "MTC treehead received_at is required", nil))
			continue
		}
		if strings.TrimSpace(entry.LogID) == "" || entry.LogID != strings.TrimSpace(entry.LogID) {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "MTC treehead log_id is required and must be canonical", nil))
			continue
		}
		expectedID, err := MTCTreeheadEntryID(entry)
		if err != nil {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, err.Error(), nil))
			continue
		}
		if entry.ID != expectedID {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "MTC treehead id mismatch", map[string]any{
				"expected": expectedID,
				"actual":   entry.ID,
			}))
			continue
		}
		if ids[entry.ID] {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "duplicate MTC treehead id", map[string]any{
				"id": entry.ID,
			}))
			continue
		}
		ids[entry.ID] = true

		message, err := mtcCheckpointMessage(&entry.Checkpoint)
		if err != nil {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, err.Error(), nil))
			continue
		}
		if entry.Checkpoint.Signature == nil {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "MTC treehead checkpoint signature is required", nil))
			continue
		}
		if err := VerifyWithPublicKey(entry.PublicKey, message, entry.Checkpoint.Signature); err != nil {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, err.Error(), nil))
			continue
		}

		key := entry.LogID + "\x00" + fmt.Sprint(entry.Checkpoint.TreeSize)
		if previousRoot, ok := rootsByLogAndSize[key]; ok && previousRoot != entry.Checkpoint.MerkleRoot {
			result.OK = false
			result.Findings = append(result.Findings, mtcTreeheadFinding("error", subject, "conflicting MTC treehead roots for the same log and tree size", map[string]any{
				"log_id":        entry.LogID,
				"tree_size":     entry.Checkpoint.TreeSize,
				"previous_root": previousRoot,
				"actual_root":   entry.Checkpoint.MerkleRoot,
			}))
			continue
		}
		rootsByLogAndSize[key] = entry.Checkpoint.MerkleRoot
		byLog[entry.LogID] = append(byLog[entry.LogID], entry)
		result.Verified++
	}

	for logID, entries := range byLog {
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Checkpoint.GeneratedAt.Equal(entries[j].Checkpoint.GeneratedAt) {
				if entries[i].Checkpoint.TreeSize == entries[j].Checkpoint.TreeSize {
					return entries[i].ID < entries[j].ID
				}
				return entries[i].Checkpoint.TreeSize < entries[j].Checkpoint.TreeSize
			}
			return entries[i].Checkpoint.GeneratedAt.Before(entries[j].Checkpoint.GeneratedAt)
		})
		maxTreeSize := -1
		for _, entry := range entries {
			if entry.Checkpoint.TreeSize < maxTreeSize {
				result.OK = false
				result.Findings = append(result.Findings, mtcTreeheadFinding("error", logID, "MTC treehead tree size moved backward over time", map[string]any{
					"tree_size":     entry.Checkpoint.TreeSize,
					"previous_size": maxTreeSize,
				}))
			}
			if entry.Checkpoint.TreeSize > maxTreeSize {
				maxTreeSize = entry.Checkpoint.TreeSize
			}
		}
	}

	if !result.OK {
		return result, fmt.Errorf("MTC treehead cache verification failed")
	}
	return result, nil
}

func ParseMTCTreeheadSource(data []byte, source string, publicKey *PublicKey, logID string, now time.Time) (MTCTreeheadCache, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return MTCTreeheadCache{}, err
	}
	switch header.Schema {
	case MTCTreeheadCacheSchema:
		var cache MTCTreeheadCache
		if err := decodeJSONStrict(data, &cache); err != nil {
			return MTCTreeheadCache{}, err
		}
		cache.Source = strings.TrimSpace(source)
		cache.FetchedAt = mtcTimestamp(now)
		for i := range cache.Treeheads {
			if cache.Treeheads[i].Source == "" {
				cache.Treeheads[i].Source = cache.Source
			}
			cache.Treeheads[i].ReceivedAt = cache.FetchedAt
		}
		return cache, nil
	case MTCCheckpointSchema:
		if publicKey == nil {
			return MTCTreeheadCache{}, fmt.Errorf("single-checkpoint treehead source requires a public key")
		}
		var checkpoint MTCCheckpoint
		if err := decodeJSONStrict(data, &checkpoint); err != nil {
			return MTCTreeheadCache{}, err
		}
		entry, err := NewMTCTreeheadEntry(source, logID, checkpoint, *publicKey, now)
		if err != nil {
			return MTCTreeheadCache{}, err
		}
		return NewMTCTreeheadCache(source, []MTCTreeheadEntry{entry}, now), nil
	default:
		return MTCTreeheadCache{}, fmt.Errorf("unsupported MTC treehead source schema %q", header.Schema)
	}
}

func DefaultMTCTreeheadLogID(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	parsed, err := url.Parse(source)
	if err == nil && parsed.Host != "" {
		out := parsed.Host
		cleanPath := path.Clean(parsed.Path)
		if cleanPath != "." && cleanPath != "/" {
			out += cleanPath
		}
		return out
	}
	return source
}

func mtcTreeheadFinding(severity, subject, message string, evidence map[string]any) MTCTreeheadFinding {
	return MTCTreeheadFinding{
		Severity: severity,
		Subject:  subject,
		Message:  message,
		Evidence: evidence,
	}
}

func decodeJSONStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unexpected trailing JSON data")
}
