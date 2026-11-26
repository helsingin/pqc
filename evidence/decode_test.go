package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/helsingin/pqc"
)

func TestDecodeRejectsAmbiguousAndMalformedDocuments(t *testing.T) {
	statement, _, keys := fixture(t, pqc.AlgorithmMLDSA65)
	document := Envelope{Schema: Schema, Statement: statement, Signatures: []Signature{}}
	valid, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(valid); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(decoded, []byte("retained evidence"), statement.Policy, keys, time.Unix(statement.ClaimedAt+1, 0)); err == nil {
		t.Fatal("inspection accepted as verification")
	}
	tests := map[string][]byte{
		"duplicate member":        bytes.Replace(valid, []byte(`"schema":`), []byte(`"schema":"ignored","schema":`), 1),
		"case alias":              bytes.Replace(valid, []byte(`"schema":`), []byte(`"Schema":`), 1),
		"unknown field":           append([]byte(`{"unknown":1,`), valid[1:]...),
		"missing field":           bytes.Replace(valid, []byte(`"schema":"pqc.evidence.v2",`), nil, 1),
		"null statement":          []byte(`{"schema":"pqc.evidence.v2","statement":null,"signatures":[]}`),
		"trailing value":          append(bytes.Clone(valid), []byte(` {}`)...),
		"oversize":                bytes.Repeat([]byte(" "), MaxDocumentBytes+1),
		"nesting":                 []byte(strings.Repeat("[", 34) + strings.Repeat("]", 34)),
		"unknown version":         bytes.Replace(valid, []byte(Schema), []byte("pqc.evidence.v99"), 1),
		"unknown policy":          bytes.Replace(valid, []byte(PolicySchema), []byte("pqc.evidence-policy.v99"), 1),
		"invalid UTF8":            bytes.Replace(valid, []byte("tenant-a"), []byte{255}, 1),
		"unpaired high surrogate": bytes.Replace(valid, []byte("tenant-a"), []byte(`\ud800`), 1),
		"unpaired low surrogate":  bytes.Replace(valid, []byte("tenant-a"), []byte(`\udc00`), 1),
		"negative length":         bytes.Replace(valid, []byte(`"length":17`), []byte(`"length":-1`), 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(data); err == nil {
				t.Fatal("malformed document accepted")
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema":"pqc.evidence.v2"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDocumentBytes+1 {
			return
		}
		_, _ = Decode(data)
	})
}
