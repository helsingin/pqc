package evidence

import (
	"fmt"

	"github.com/helsingin/pqc/internal/strictjson"
)

// Decode validates structure, not authenticity. Call Verify with independently
// trusted policy/keys and the payload before accepting any evidence claims.
func Decode(data []byte) (*Envelope, error) {
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("evidence: document exceeds 1 MiB")
	}
	var document Envelope
	if err := strictjson.Decode(data, &document, true); err != nil {
		return nil, fmt.Errorf("evidence: JSON: %w", err)
	}
	if document.Schema != Schema {
		return nil, fmt.Errorf("evidence: unsupported schema")
	}
	if err := validateStatement(document.Statement); err != nil {
		return nil, err
	}
	if len(document.Signatures) > len(document.Statement.Policy.Signers) {
		return nil, fmt.Errorf("evidence: too many signatures")
	}
	for i, signature := range document.Signatures {
		_, size := sizes(document.Statement.Policy.Signers[i].Algorithm)
		if signature.Signer != i || len(signature.Value) != size {
			return nil, fmt.Errorf("evidence: malformed signature at index %d", i)
		}
	}
	return &document, nil
}

// Inspect returns unauthenticated claims only. It explicitly permits unsigned
// documents, never reports verification success, and is not a fallback verifier.
func Inspect(data []byte) (*Statement, error) {
	document, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return &document.Statement, nil
}
