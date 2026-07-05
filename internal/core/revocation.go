package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	RevocationManifestSchema = "pqc.revocation-manifest.v1"
)

type RevocationManifest struct {
	Schema    string            `json:"schema"`
	Hash      string            `json:"hash"`
	CreatedAt time.Time         `json:"created_at"`
	Events    []RevocationEvent `json:"events,omitempty"`
}

type RevocationEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Subject   string         `json:"subject"`
	Reason    string         `json:"reason"`
	RevokedAt time.Time      `json:"revoked_at"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func NewRevocationManifest(now time.Time) RevocationManifest {
	return RevocationManifest{
		Schema:    RevocationManifestSchema,
		Hash:      MerkleHashSHA256,
		CreatedAt: mtcTimestamp(now),
	}
}

func ParseRevocationSubject(subjectType, subject string) (string, string, error) {
	subjectType = strings.TrimSpace(strings.ToLower(subjectType))
	subject = strings.TrimSpace(subject)
	if subjectType == "" || subject == "" {
		return "", "", fmt.Errorf("revocation subject type and subject are required")
	}
	switch subjectType {
	case "key":
		return "key", subject, nil
	case "mtc-leaf":
		index, err := strconv.Atoi(subject)
		if err != nil || index < 0 {
			return "", "", fmt.Errorf("MTC leaf revocation subject must be a non-negative index")
		}
		return "mtc-leaf", strconv.Itoa(index), nil
	default:
		return "", "", fmt.Errorf("unsupported revocation subject type %q", subjectType)
	}
}

func (m *RevocationManifest) Add(subjectType, subject, reason string, metadata map[string]any, now time.Time) (RevocationEvent, error) {
	if err := m.validate(); err != nil {
		return RevocationEvent{}, err
	}
	subjectType, subject, err := ParseRevocationSubject(subjectType, subject)
	if err != nil {
		return RevocationEvent{}, err
	}
	reason = normalizeRevocationReason(reason)
	if reason == "" {
		return RevocationEvent{}, fmt.Errorf("revocation reason is required")
	}
	metadataCopy, err := cloneRevocationMetadata(metadata)
	if err != nil {
		return RevocationEvent{}, err
	}
	event := RevocationEvent{
		Type:      subjectType,
		Subject:   subject,
		Reason:    reason,
		RevokedAt: mtcTimestamp(now),
		Metadata:  metadataCopy,
	}
	id, err := RevocationEventID(event)
	if err != nil {
		return RevocationEvent{}, err
	}
	event.ID = id
	for _, existing := range m.Events {
		if existing.ID == event.ID {
			return RevocationEvent{}, fmt.Errorf("revocation event already exists: %s", event.ID)
		}
		if existing.Type == event.Type && existing.Subject == event.Subject {
			return RevocationEvent{}, fmt.Errorf("revocation subject already exists: %s/%s", event.Type, event.Subject)
		}
	}
	m.Events = append(m.Events, event)
	return event, nil
}

func ValidateRevocationManifest(manifest RevocationManifest) error {
	return manifest.validate()
}

func RevocationEventID(event RevocationEvent) (string, error) {
	event.ID = ""
	if err := validateRevocationEvent(event); err != nil {
		return "", err
	}
	data, err := revocationEventMessage(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ReadRevocationManifest(r io.Reader) (RevocationManifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return RevocationManifest{}, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return NewRevocationManifest(time.Now().UTC()), nil
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err == nil && header.Schema == RevocationManifestSchema {
		var manifest RevocationManifest
		if err := decodeRevocationJSON(data, &manifest); err != nil {
			return RevocationManifest{}, err
		}
		if err := manifest.validate(); err != nil {
			return RevocationManifest{}, err
		}
		return manifest, nil
	}
	events, err := readRevocationJSONL(data)
	if err != nil {
		return RevocationManifest{}, err
	}
	manifest := NewRevocationManifest(time.Now().UTC())
	manifest.Events = events
	if err := manifest.validate(); err != nil {
		return RevocationManifest{}, err
	}
	return manifest, nil
}

func WriteRevocationManifest(w io.Writer, manifest RevocationManifest) error {
	if err := manifest.validate(); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(manifest)
}

func RevocationManifestRoot(manifest RevocationManifest) (string, error) {
	if err := manifest.validate(); err != nil {
		return "", err
	}
	leaves, err := revocationLeaves(manifest)
	if err != nil {
		return "", err
	}
	return MerkleRootHex(leaves), nil
}

func RevocationManifestDigest(manifest RevocationManifest) (string, error) {
	if err := manifest.validate(); err != nil {
		return "", err
	}
	digest := sha256.New()
	for _, event := range manifest.Events {
		data, err := revocationEventMessage(event)
		if err != nil {
			return "", err
		}
		digest.Write(data)
		digest.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func (m RevocationManifest) validate() error {
	if m.Schema != RevocationManifestSchema {
		return fmt.Errorf("unsupported revocation manifest schema %q", m.Schema)
	}
	if m.Hash != MerkleHashSHA256 {
		return fmt.Errorf("unsupported revocation manifest hash %q", m.Hash)
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("revocation manifest created_at is required")
	}
	ids := map[string]bool{}
	subjects := map[string]bool{}
	for i, event := range m.Events {
		if err := validateRevocationEvent(event); err != nil {
			return fmt.Errorf("revocation event %d: %w", i, err)
		}
		expectedID, err := RevocationEventID(event)
		if err != nil {
			return fmt.Errorf("revocation event %d: %w", i, err)
		}
		if event.ID != expectedID {
			return fmt.Errorf("revocation event %d id mismatch", i)
		}
		if ids[event.ID] {
			return fmt.Errorf("duplicate revocation event id %s", event.ID)
		}
		ids[event.ID] = true
		subjectKey := event.Type + "\x00" + event.Subject
		if subjects[subjectKey] {
			return fmt.Errorf("duplicate revocation subject %s/%s", event.Type, event.Subject)
		}
		subjects[subjectKey] = true
	}
	return nil
}

func validateRevocationEvent(event RevocationEvent) error {
	if event.Type == "" || event.Type != strings.TrimSpace(strings.ToLower(event.Type)) {
		return fmt.Errorf("revocation type is required and must be canonical")
	}
	canonicalType, canonicalSubject, err := ParseRevocationSubject(event.Type, event.Subject)
	if err != nil {
		return err
	}
	if event.Type != canonicalType || event.Subject != canonicalSubject {
		return fmt.Errorf("revocation subject is not canonical")
	}
	if normalizeRevocationReason(event.Reason) == "" || event.Reason != normalizeRevocationReason(event.Reason) {
		return fmt.Errorf("revocation reason is required and must be canonical")
	}
	if event.RevokedAt.IsZero() {
		return fmt.Errorf("revoked_at is required")
	}
	return nil
}

func readRevocationJSONL(data []byte) ([]RevocationEvent, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var events []RevocationEvent
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event RevocationEvent
		if err := decodeRevocationJSON([]byte(line), &event); err != nil {
			return nil, err
		}
		expectedID, err := RevocationEventID(event)
		if err != nil {
			return nil, err
		}
		if event.ID != expectedID {
			return nil, fmt.Errorf("revocation event id mismatch")
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func revocationLeaves(manifest RevocationManifest) ([][]byte, error) {
	leaves := make([][]byte, 0, len(manifest.Events))
	for _, event := range manifest.Events {
		data, err := revocationEventMessage(event)
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

func revocationEventMessage(event RevocationEvent) ([]byte, error) {
	return json.Marshal(struct {
		Type      string         `json:"type"`
		Subject   string         `json:"subject"`
		Reason    string         `json:"reason"`
		RevokedAt time.Time      `json:"revoked_at"`
		Metadata  map[string]any `json:"metadata,omitempty"`
	}{
		Type:      event.Type,
		Subject:   event.Subject,
		Reason:    event.Reason,
		RevokedAt: event.RevokedAt.UTC(),
		Metadata:  event.Metadata,
	})
}

func normalizeRevocationReason(reason string) string {
	reason = strings.TrimSpace(strings.ToLower(reason))
	reason = strings.ReplaceAll(reason, "_", "-")
	return reason
}

func cloneRevocationMetadata(in map[string]any) (map[string]any, error) {
	if len(in) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeRevocationJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return fmt.Errorf("unexpected trailing JSON data")
}
