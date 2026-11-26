package evidence

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helsingin/pqc"
)

type vector struct {
	Description     string          `json:"description"`
	Payload         []byte          `json:"payload"`
	Now             int64           `json:"now"`
	Keys            []pqc.PublicKey `json:"keys"`
	Document        *Envelope       `json:"document"`
	SigningBytesHex string          `json:"signing_bytes_hex"`
	SigningSHA512   string          `json:"signing_sha512"`
}

// Explicit fixture maintenance only. Private test keys stay in t.TempDir and
// are removed automatically. Python independently fills the canonical fields.
func TestWritePublicVector(t *testing.T) {
	if os.Getenv("PQC_UPDATE_EVIDENCE_VECTOR") != "1" {
		t.Skip("fixture maintenance only")
	}
	initial, providers, keys := fixture(t, pqc.AlgorithmMLDSA65, pqc.AlgorithmMLDSA87, pqc.AlgorithmSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2256s)
	payload := []byte("evidence\x00payload: π\n")
	statement, err := NewStatement(initial.Policy, payload, "application/octet-stream", time.Unix(initial.ClaimedAt, 0), []Field{{Key: "é", Value: "composed"}, {Key: "e\u0301", Value: "decomposed"}, {Key: "A", Value: "quoted \"value\" and 💡"}})
	if err != nil {
		t.Fatal(err)
	}
	document, err := Sign(t.Context(), statement, providers, false)
	if err != nil {
		t.Fatal(err)
	}
	value := vector{Description: "Public-only all-four-algorithm evidence fixture; canonical bytes independently encoded by scripts/check-evidence-vectors.py", Payload: payload, Now: statement.ClaimedAt + 1, Keys: keys, Document: document}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "evidence-v2.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalAndPublicVerificationVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "evidence-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value vector
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	actual, err := SigningBytes(value.Document.Statement)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(value.SigningBytesHex)
	if err != nil || !bytes.Equal(expected, actual) {
		t.Fatalf("independent canonical bytes differ: %v", err)
	}
	hash := sha512.Sum512(actual)
	if hex.EncodeToString(hash[:]) != value.SigningSHA512 {
		t.Fatal("independent canonical digest differs")
	}
	if err := Verify(value.Document, value.Payload, value.Document.Statement.Policy, value.Keys, time.Unix(value.Now, 0)); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(value.Document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(decoded, value.Payload, value.Document.Statement.Policy, value.Keys, time.Unix(value.Now, 0)); err != nil {
		t.Fatal(err)
	}
}
