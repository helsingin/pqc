package core

import (
	"context"
	"time"
)

// Store persists versioned key material. Implementations are responsible for
// protecting private keys at rest.
type Store interface {
	Put(ctx context.Context, record KeyRecord) error
	Get(ctx context.Context, id string) (KeyRecord, error)
	GetVersion(ctx context.Context, id string, version int) (KeyRecord, error)
	List(ctx context.Context) ([]KeyMetadata, error)
}

type KeyRecord struct {
	ID         string    `json:"id"`
	Algorithm  Algorithm `json:"algorithm"`
	Use        KeyUse    `json:"use"`
	Version    int       `json:"version"`
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
}

type KeyMetadata struct {
	ID        string    `json:"id"`
	Algorithm Algorithm `json:"algorithm"`
	Use       KeyUse    `json:"use"`
	Version   int       `json:"version"`
	PublicKey []byte    `json:"public_key,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type GenerateRequest struct {
	ID        string
	Algorithm Algorithm
}

type EncryptOptions struct {
	AAD []byte
}

type SignOptions struct {
	Context    []byte
	Randomized bool
}

type PublicKey struct {
	ID        string    `json:"id"`
	Algorithm Algorithm `json:"algorithm"`
	Use       KeyUse    `json:"use"`
	Version   int       `json:"version"`
	PublicKey []byte    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

func metadataFromRecord(record KeyRecord, includePublic bool) KeyMetadata {
	meta := KeyMetadata{
		ID:        record.ID,
		Algorithm: record.Algorithm,
		Use:       record.Use,
		Version:   record.Version,
		CreatedAt: record.CreatedAt,
	}
	if includePublic {
		meta.PublicKey = append([]byte(nil), record.PublicKey...)
	}
	return meta
}
