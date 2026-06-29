package pqc

import "time"

const (
	EnvelopeSchema  = "pqc.envelope.v1"
	SignatureSchema = "pqc.signature.v1"

	KDFHKDFSHA256 = "HKDF-SHA256"
	AEADAES256GCM = "AES-256-GCM"
)

// Envelope contains an ML-KEM encapsulated content-encryption key and an AEAD
// ciphertext. Byte slices are base64 encoded when marshaled as JSON.
type Envelope struct {
	Schema          string    `json:"schema"`
	KeyID           string    `json:"key_id"`
	KeyVersion      int       `json:"key_version"`
	KEM             Algorithm `json:"kem"`
	KDF             string    `json:"kdf"`
	AEAD            string    `json:"aead"`
	Salt            []byte    `json:"salt"`
	EncapsulatedKey []byte    `json:"encapsulated_key"`
	Nonce           []byte    `json:"nonce"`
	Ciphertext      []byte    `json:"ciphertext"`
	CreatedAt       time.Time `json:"created_at"`
}

// SignatureEnvelope carries an ML-DSA signature plus enough metadata to verify
// it later using the manager's key store.
type SignatureEnvelope struct {
	Schema     string    `json:"schema"`
	KeyID      string    `json:"key_id"`
	KeyVersion int       `json:"key_version"`
	Algorithm  Algorithm `json:"algorithm"`
	Context    []byte    `json:"context,omitempty"`
	Signature  []byte    `json:"signature"`
	CreatedAt  time.Time `json:"created_at"`
}
