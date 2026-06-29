package pqc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type Manager struct {
	store   Store
	rand    io.Reader
	now     func() time.Time
	auditor Auditor
}

type Option func(*Manager)

func WithRand(randReader io.Reader) Option {
	return func(m *Manager) {
		if randReader != nil {
			m.rand = randReader
		}
	}
}

func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

func WithAuditor(auditor Auditor) Option {
	return func(m *Manager) {
		m.auditor = auditor
	}
}

func NewManager(store Store, opts ...Option) *Manager {
	m := &Manager{
		store: store,
		rand:  rand.Reader,
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) Generate(ctx context.Context, req GenerateRequest) (meta *KeyMetadata, err error) {
	event := AuditEvent{
		Operation: "key.generate",
		KeyID:     req.ID,
		Algorithm: req.Algorithm,
	}
	defer func() {
		if meta != nil {
			event.KeyVersion = meta.Version
			event.Algorithm = meta.Algorithm
		}
		m.recordAudit(ctx, event, err)
	}()

	if err := validateKeyID(req.ID); err != nil {
		return nil, err
	}
	if err := req.Algorithm.Validate(); err != nil {
		return nil, err
	}
	if _, err := m.store.Get(ctx, req.ID); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyExists, req.ID)
	} else if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	record, err := m.generateRecord(req.ID, req.Algorithm, 1)
	if err != nil {
		return nil, err
	}
	if err := m.store.Put(ctx, record); err != nil {
		return nil, err
	}
	generated := metadataFromRecord(record, true)
	return &generated, nil
}

func (m *Manager) Rotate(ctx context.Context, id string) (meta *KeyMetadata, err error) {
	event := AuditEvent{
		Operation: "key.rotate",
		KeyID:     id,
	}
	defer func() {
		if meta != nil {
			event.Algorithm = meta.Algorithm
			event.KeyVersion = meta.Version
		}
		m.recordAudit(ctx, event, err)
	}()

	latest, err := m.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	event.Algorithm = latest.Algorithm
	event.KeyVersion = latest.Version
	record, err := m.generateRecord(id, latest.Algorithm, latest.Version+1)
	if err != nil {
		return nil, err
	}
	if err := m.store.Put(ctx, record); err != nil {
		return nil, err
	}
	rotated := metadataFromRecord(record, true)
	return &rotated, nil
}

func (m *Manager) Get(ctx context.Context, id string) (meta *KeyMetadata, err error) {
	event := AuditEvent{
		Operation: "key.get",
		KeyID:     id,
	}
	defer func() {
		if meta != nil {
			event.Algorithm = meta.Algorithm
			event.KeyVersion = meta.Version
		}
		m.recordAudit(ctx, event, err)
	}()

	record, err := m.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	got := metadataFromRecord(record, true)
	return &got, nil
}

func (m *Manager) List(ctx context.Context) (keys []KeyMetadata, err error) {
	event := AuditEvent{Operation: "key.list"}
	defer func() {
		m.recordAudit(ctx, event, err)
	}()
	return m.store.List(ctx)
}

func (m *Manager) ExportPublic(ctx context.Context, id string) (publicKey *PublicKey, err error) {
	event := AuditEvent{
		Operation: "key.public",
		KeyID:     id,
	}
	defer func() {
		if publicKey != nil {
			event.Algorithm = publicKey.Algorithm
			event.KeyVersion = publicKey.Version
		}
		m.recordAudit(ctx, event, err)
	}()

	record, err := m.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		ID:        record.ID,
		Algorithm: record.Algorithm,
		Use:       record.Use,
		Version:   record.Version,
		PublicKey: append([]byte(nil), record.PublicKey...),
		CreatedAt: record.CreatedAt,
	}, nil
}

func (m *Manager) Encrypt(ctx context.Context, keyID string, plaintext []byte, opts EncryptOptions) (envelope *Envelope, err error) {
	event := AuditEvent{
		Operation: "encrypt",
		KeyID:     keyID,
	}
	defer func() {
		if envelope != nil {
			event.Algorithm = envelope.KEM
			event.KeyVersion = envelope.KeyVersion
		}
		m.recordAudit(ctx, event, err)
	}()

	record, err := m.store.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}
	event.Algorithm = record.Algorithm
	event.KeyVersion = record.Version
	if record.Algorithm != AlgorithmMLKEM768 {
		return nil, fmt.Errorf("encryption requires %s key, got %s", AlgorithmMLKEM768, record.Algorithm)
	}
	if len(record.PublicKey) != kyber768.PublicKeySize {
		return nil, fmt.Errorf("invalid %s public key length: %d", record.Algorithm, len(record.PublicKey))
	}

	pub := new(kyber768.PublicKey)
	pub.Unpack(record.PublicKey)

	kemCiphertext := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	seed := make([]byte, kyber768.EncapsulationSeedSize)
	if _, err := io.ReadFull(m.rand, seed); err != nil {
		return nil, fmt.Errorf("read encapsulation seed: %w", err)
	}
	pub.EncapsulateTo(kemCiphertext, sharedSecret, seed)
	defer zero(sharedSecret)
	defer zero(seed)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(m.rand, salt); err != nil {
		return nil, fmt.Errorf("read hkdf salt: %w", err)
	}
	aeadKey, err := deriveAEADKey(sharedSecret, salt, record)
	if err != nil {
		return nil, err
	}
	defer zero(aeadKey)

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(m.rand, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	return &Envelope{
		Schema:          EnvelopeSchema,
		KeyID:           record.ID,
		KeyVersion:      record.Version,
		KEM:             record.Algorithm,
		KDF:             KDFHKDFSHA256,
		AEAD:            AEADAES256GCM,
		Salt:            salt,
		EncapsulatedKey: kemCiphertext,
		Nonce:           nonce,
		Ciphertext:      gcm.Seal(nil, nonce, plaintext, opts.AAD),
		CreatedAt:       m.now().UTC(),
	}, nil
}

func (m *Manager) Decrypt(ctx context.Context, envelope *Envelope, opts EncryptOptions) (plaintext []byte, err error) {
	event := AuditEvent{Operation: "decrypt"}
	if envelope != nil {
		event.KeyID = envelope.KeyID
		event.Algorithm = envelope.KEM
		event.KeyVersion = envelope.KeyVersion
	}
	defer func() {
		m.recordAudit(ctx, event, err)
	}()

	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	record, err := m.store.GetVersion(ctx, envelope.KeyID, envelope.KeyVersion)
	if err != nil {
		return nil, err
	}
	if record.Algorithm != AlgorithmMLKEM768 || envelope.KEM != AlgorithmMLKEM768 {
		return nil, fmt.Errorf("%w: expected %s", ErrInvalidEnvelope, AlgorithmMLKEM768)
	}
	if len(record.PrivateKey) != kyber768.PrivateKeySize {
		return nil, fmt.Errorf("invalid %s private key length: %d", record.Algorithm, len(record.PrivateKey))
	}

	priv := new(kyber768.PrivateKey)
	priv.Unpack(record.PrivateKey)

	sharedSecret := make([]byte, kyber768.SharedKeySize)
	priv.DecapsulateTo(sharedSecret, envelope.EncapsulatedKey)
	defer zero(sharedSecret)

	aeadKey, err := deriveAEADKey(sharedSecret, envelope.Salt, record)
	if err != nil {
		return nil, err
	}
	defer zero(aeadKey)

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce length %d", ErrInvalidEnvelope, len(envelope.Nonce))
	}
	opened, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, opts.AAD)
	if err != nil {
		return nil, fmt.Errorf("decrypt envelope: %w", err)
	}
	return opened, nil
}

func (m *Manager) Sign(ctx context.Context, keyID string, message []byte, opts SignOptions) (signature *SignatureEnvelope, err error) {
	event := AuditEvent{
		Operation: "sign",
		KeyID:     keyID,
	}
	defer func() {
		if signature != nil {
			event.Algorithm = signature.Algorithm
			event.KeyVersion = signature.KeyVersion
		}
		m.recordAudit(ctx, event, err)
	}()

	if len(opts.Context) > 255 {
		return nil, fmt.Errorf("signature context must be at most 255 bytes")
	}
	record, err := m.store.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}
	event.Algorithm = record.Algorithm
	event.KeyVersion = record.Version
	if record.Use != KeyUseSignature {
		return nil, fmt.Errorf("signing requires signature key, got %s", record.Algorithm)
	}

	sigBytes, err := signRecord(record, message, opts)
	if err != nil {
		return nil, err
	}
	return &SignatureEnvelope{
		Schema:     SignatureSchema,
		KeyID:      record.ID,
		KeyVersion: record.Version,
		Algorithm:  record.Algorithm,
		Context:    append([]byte(nil), opts.Context...),
		Signature:  sigBytes,
		CreatedAt:  m.now().UTC(),
	}, nil
}

func (m *Manager) Verify(ctx context.Context, message []byte, sig *SignatureEnvelope) (err error) {
	event := AuditEvent{Operation: "verify"}
	if sig != nil {
		event.KeyID = sig.KeyID
		event.Algorithm = sig.Algorithm
		event.KeyVersion = sig.KeyVersion
	}
	defer func() {
		m.recordAudit(ctx, event, err)
	}()

	if err := validateSignature(sig); err != nil {
		return err
	}
	record, err := m.store.GetVersion(ctx, sig.KeyID, sig.KeyVersion)
	if err != nil {
		return err
	}
	if record.Algorithm != sig.Algorithm {
		return fmt.Errorf("%w: key algorithm %s does not match signature algorithm %s", ErrInvalidSignature, record.Algorithm, sig.Algorithm)
	}
	return verifyRecord(record, message, sig)
}

// VerifyWithPublicKey verifies a signature envelope against an exported public
// key without opening a private key store.
func VerifyWithPublicKey(publicKey PublicKey, message []byte, sig *SignatureEnvelope) error {
	if err := validateSignature(sig); err != nil {
		return err
	}
	if publicKey.ID != sig.KeyID {
		return fmt.Errorf("%w: public key id %q does not match signature key id %q", ErrInvalidSignature, publicKey.ID, sig.KeyID)
	}
	if publicKey.Version != sig.KeyVersion {
		return fmt.Errorf("%w: public key version %d does not match signature key version %d", ErrInvalidSignature, publicKey.Version, sig.KeyVersion)
	}
	if publicKey.Algorithm != sig.Algorithm {
		return fmt.Errorf("%w: public key algorithm %s does not match signature algorithm %s", ErrInvalidSignature, publicKey.Algorithm, sig.Algorithm)
	}
	return verifyRecord(KeyRecord{
		ID:        publicKey.ID,
		Algorithm: publicKey.Algorithm,
		Use:       publicKey.Use,
		Version:   publicKey.Version,
		PublicKey: append([]byte(nil), publicKey.PublicKey...),
		CreatedAt: publicKey.CreatedAt,
	}, message, sig)
}

func (m *Manager) recordAudit(ctx context.Context, event AuditEvent, operationErr error) {
	if m.auditor == nil {
		return
	}
	event.Time = m.now().UTC()
	event.Success = operationErr == nil
	if operationErr != nil {
		event.Error = operationErr.Error()
	}
	_ = m.auditor.Record(ctx, event)
}

func (m *Manager) generateRecord(id string, algorithm Algorithm, version int) (KeyRecord, error) {
	use, err := algorithm.Use()
	if err != nil {
		return KeyRecord{}, err
	}
	publicKey, privateKey, err := generateKeyPair(algorithm, m.rand)
	if err != nil {
		return KeyRecord{}, err
	}
	return KeyRecord{
		ID:         id,
		Algorithm:  algorithm,
		Use:        use,
		Version:    version,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		CreatedAt:  m.now().UTC(),
	}, nil
}

func deriveAEADKey(sharedSecret, salt []byte, record KeyRecord) ([]byte, error) {
	info := fmt.Sprintf("pqc:%s:%s:%s:%d:%s", EnvelopeSchema, record.Algorithm, record.ID, record.Version, AEADAES256GCM)
	key, err := hkdf.Key(sha256.New, sharedSecret, salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("derive aead key: %w", err)
	}
	return key, nil
}

func generateKeyPair(algorithm Algorithm, randReader io.Reader) ([]byte, []byte, error) {
	switch algorithm {
	case AlgorithmMLKEM768:
		pub, priv, err := kyber768.GenerateKeyPair(randReader)
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := pub.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		return publicKey, privateKey, nil
	case AlgorithmMLDSA65:
		pub, priv, err := mldsa65.GenerateKey(randReader)
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := pub.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		return publicKey, privateKey, nil
	case AlgorithmMLDSA87:
		pub, priv, err := mldsa87.GenerateKey(randReader)
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := pub.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		return publicKey, privateKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func signRecord(record KeyRecord, message []byte, opts SignOptions) ([]byte, error) {
	switch record.Algorithm {
	case AlgorithmMLDSA65:
		if len(record.PrivateKey) != mldsa65.PrivateKeySize {
			return nil, fmt.Errorf("invalid %s private key length: %d", record.Algorithm, len(record.PrivateKey))
		}
		priv := new(mldsa65.PrivateKey)
		if err := priv.UnmarshalBinary(record.PrivateKey); err != nil {
			return nil, err
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(priv, message, opts.Context, opts.Randomized, sig); err != nil {
			return nil, err
		}
		return sig, nil
	case AlgorithmMLDSA87:
		if len(record.PrivateKey) != mldsa87.PrivateKeySize {
			return nil, fmt.Errorf("invalid %s private key length: %d", record.Algorithm, len(record.PrivateKey))
		}
		priv := new(mldsa87.PrivateKey)
		if err := priv.UnmarshalBinary(record.PrivateKey); err != nil {
			return nil, err
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(priv, message, opts.Context, opts.Randomized, sig); err != nil {
			return nil, err
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("signing not supported for %s", record.Algorithm)
	}
}

func verifyRecord(record KeyRecord, message []byte, sig *SignatureEnvelope) error {
	if len(sig.Context) > 255 {
		return fmt.Errorf("%w: context exceeds 255 bytes", ErrInvalidSignature)
	}
	switch record.Algorithm {
	case AlgorithmMLDSA65:
		if len(record.PublicKey) != mldsa65.PublicKeySize {
			return fmt.Errorf("invalid %s public key length: %d", record.Algorithm, len(record.PublicKey))
		}
		pub := new(mldsa65.PublicKey)
		if err := pub.UnmarshalBinary(record.PublicKey); err != nil {
			return err
		}
		if !mldsa65.Verify(pub, message, sig.Context, sig.Signature) {
			return fmt.Errorf("%w: verification failed", ErrInvalidSignature)
		}
		return nil
	case AlgorithmMLDSA87:
		if len(record.PublicKey) != mldsa87.PublicKeySize {
			return fmt.Errorf("invalid %s public key length: %d", record.Algorithm, len(record.PublicKey))
		}
		pub := new(mldsa87.PublicKey)
		if err := pub.UnmarshalBinary(record.PublicKey); err != nil {
			return err
		}
		if !mldsa87.Verify(pub, message, sig.Context, sig.Signature) {
			return fmt.Errorf("%w: verification failed", ErrInvalidSignature)
		}
		return nil
	default:
		return fmt.Errorf("verification not supported for %s", record.Algorithm)
	}
}

func validateEnvelope(envelope *Envelope) error {
	if envelope == nil {
		return fmt.Errorf("%w: nil envelope", ErrInvalidEnvelope)
	}
	if envelope.Schema != EnvelopeSchema {
		return fmt.Errorf("%w: unsupported schema %q", ErrInvalidEnvelope, envelope.Schema)
	}
	if envelope.KeyID == "" {
		return fmt.Errorf("%w: missing key_id", ErrInvalidEnvelope)
	}
	if envelope.KeyVersion < 1 {
		return fmt.Errorf("%w: invalid key_version", ErrInvalidEnvelope)
	}
	if envelope.KEM != AlgorithmMLKEM768 {
		return fmt.Errorf("%w: unsupported kem %q", ErrInvalidEnvelope, envelope.KEM)
	}
	if envelope.KDF != KDFHKDFSHA256 {
		return fmt.Errorf("%w: unsupported kdf %q", ErrInvalidEnvelope, envelope.KDF)
	}
	if envelope.AEAD != AEADAES256GCM {
		return fmt.Errorf("%w: unsupported aead %q", ErrInvalidEnvelope, envelope.AEAD)
	}
	if len(envelope.Salt) != 32 {
		return fmt.Errorf("%w: salt length %d", ErrInvalidEnvelope, len(envelope.Salt))
	}
	if len(envelope.EncapsulatedKey) != kyber768.CiphertextSize {
		return fmt.Errorf("%w: encapsulated key length %d", ErrInvalidEnvelope, len(envelope.EncapsulatedKey))
	}
	if len(envelope.Ciphertext) == 0 {
		return fmt.Errorf("%w: empty ciphertext", ErrInvalidEnvelope)
	}
	return nil
}

func validateSignature(sig *SignatureEnvelope) error {
	if sig == nil {
		return fmt.Errorf("%w: nil signature", ErrInvalidSignature)
	}
	if sig.Schema != SignatureSchema {
		return fmt.Errorf("%w: unsupported schema %q", ErrInvalidSignature, sig.Schema)
	}
	if sig.KeyID == "" {
		return fmt.Errorf("%w: missing key_id", ErrInvalidSignature)
	}
	if sig.KeyVersion < 1 {
		return fmt.Errorf("%w: invalid key_version", ErrInvalidSignature)
	}
	if sig.Algorithm != AlgorithmMLDSA65 && sig.Algorithm != AlgorithmMLDSA87 {
		return fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidSignature, sig.Algorithm)
	}
	if len(sig.Signature) == 0 {
		return fmt.Errorf("%w: empty signature", ErrInvalidSignature)
	}
	return nil
}

func validateKeyID(id string) error {
	if id == "" {
		return fmt.Errorf("key id is required")
	}
	return nil
}

func zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
