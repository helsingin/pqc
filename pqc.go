package pqc

import (
	"context"
	"io"
	"time"

	"github.com/helsingin/pqc/internal/core"
)

const (
	AlgorithmMLKEM768 = core.AlgorithmMLKEM768
	AlgorithmMLDSA65  = core.AlgorithmMLDSA65
	AlgorithmMLDSA87  = core.AlgorithmMLDSA87

	KeyUseKEM       = core.KeyUseKEM
	KeyUseSignature = core.KeyUseSignature

	EnvelopeSchema  = core.EnvelopeSchema
	SignatureSchema = core.SignatureSchema
	KDFHKDFSHA256   = core.KDFHKDFSHA256
	AEADAES256GCM   = core.AEADAES256GCM

	MerkleHashSHA256             = core.MerkleHashSHA256
	AuditCheckpointSchema        = core.AuditCheckpointSchema
	InventoryReportSchema        = core.InventoryReportSchema
	TransparencyCheckpointSchema = core.TransparencyCheckpointSchema
	TransparencyBundleSchema     = core.TransparencyBundleSchema

	MTCLogSchema           = core.MTCLogSchema
	MTCCheckpointSchema    = core.MTCCheckpointSchema
	MTCProofSchema         = core.MTCProofSchema
	MTCTreeheadCacheSchema = core.MTCTreeheadCacheSchema

	ReadinessScanSchema = core.ReadinessScanSchema

	RevocationManifestSchema = core.RevocationManifestSchema

	TLSVerificationSystem           = core.TLSVerificationSystem
	TLSVerificationCustom           = core.TLSVerificationCustom
	TLSVerificationSkipped          = core.TLSVerificationSkipped
	TLSReadinessPolicyPublicWeb2029 = core.TLSReadinessPolicyPublicWeb2029
)

var (
	ErrKeyNotFound      = core.ErrKeyNotFound
	ErrKeyExists        = core.ErrKeyExists
	ErrInvalidEnvelope  = core.ErrInvalidEnvelope
	ErrInvalidSignature = core.ErrInvalidSignature
)

type (
	Algorithm = core.Algorithm
	KeyUse    = core.KeyUse

	Envelope          = core.Envelope
	SignatureEnvelope = core.SignatureEnvelope

	Store           = core.Store
	KeyRecord       = core.KeyRecord
	KeyMetadata     = core.KeyMetadata
	GenerateRequest = core.GenerateRequest
	EncryptOptions  = core.EncryptOptions
	SignOptions     = core.SignOptions
	PublicKey       = core.PublicKey

	Manager = core.Manager
	Option  = core.Option

	AuditEvent  = core.AuditEvent
	Auditor     = core.Auditor
	AuditorFunc = core.AuditorFunc
	FileAuditor = core.FileAuditor

	AuditCheckpoint        = core.AuditCheckpoint
	InventoryEntry         = core.InventoryEntry
	InventoryReport        = core.InventoryReport
	TransparencyCheckpoint = core.TransparencyCheckpoint
	TransparencyBundle     = core.TransparencyBundle

	RevocationManifest = core.RevocationManifest
	RevocationEvent    = core.RevocationEvent

	TLSInspectOptions  = core.TLSInspectOptions
	TLSReport          = core.TLSReport
	TLSCertificate     = core.TLSCertificate
	TLSReadinessPolicy = core.TLSReadinessPolicy
	TLSReadiness       = core.TLSReadiness
	ReadinessFinding   = core.ReadinessFinding

	ReadinessScan     = core.ReadinessScan
	ReadinessCategory = core.ReadinessCategory
	ReadinessCoverage = core.ReadinessCoverage

	MTCLog        = core.MTCLog
	MTCLogEntry   = core.MTCLogEntry
	MTCCheckpoint = core.MTCCheckpoint
	MTCProof      = core.MTCProof
	MTCProofNode  = core.MTCProofNode

	MTCTreeheadCache        = core.MTCTreeheadCache
	MTCTreeheadEntry        = core.MTCTreeheadEntry
	MTCTreeheadVerifyResult = core.MTCTreeheadVerifyResult
	MTCTreeheadFinding      = core.MTCTreeheadFinding
)

func ParseAlgorithm(value string) (Algorithm, error) {
	return core.ParseAlgorithm(value)
}

func NewManager(store Store, opts ...Option) *Manager {
	return core.NewManager(store, opts...)
}

func WithRand(randReader io.Reader) Option {
	return core.WithRand(randReader)
}

func WithClock(now func() time.Time) Option {
	return core.WithClock(now)
}

func WithAuditor(auditor Auditor) Option {
	return core.WithAuditor(auditor)
}

func VerifyWithPublicKey(publicKey PublicKey, message []byte, sig *SignatureEnvelope) error {
	return core.VerifyWithPublicKey(publicKey, message, sig)
}

func NewFileAuditor(path string) (*FileAuditor, error) {
	return core.NewFileAuditor(path)
}

func BuildAuditCheckpoint(r io.Reader, now time.Time) (*AuditCheckpoint, error) {
	return core.BuildAuditCheckpoint(r, now)
}

func SignAuditCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *AuditCheckpoint, signKey string) error {
	return core.SignAuditCheckpoint(ctx, manager, checkpoint, signKey)
}

func VerifyAuditCheckpoint(r io.Reader, checkpoint *AuditCheckpoint, publicKey *PublicKey) error {
	return core.VerifyAuditCheckpoint(r, checkpoint, publicKey)
}

func BuildInventoryReport(keys []KeyMetadata, targets []TLSReport, now time.Time) InventoryReport {
	return core.BuildInventoryReport(keys, targets, now)
}

func BuildTransparencyCheckpoint(report InventoryReport, now time.Time) (*TransparencyCheckpoint, error) {
	return core.BuildTransparencyCheckpoint(report, now)
}

func BuildTransparencyCheckpointWithRevocations(report InventoryReport, revocations *RevocationManifest, now time.Time) (*TransparencyCheckpoint, error) {
	return core.BuildTransparencyCheckpointWithRevocations(report, revocations, now)
}

func SignTransparencyCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *TransparencyCheckpoint, signKey string) error {
	return core.SignTransparencyCheckpoint(ctx, manager, checkpoint, signKey)
}

func VerifyTransparencyCheckpoint(report InventoryReport, checkpoint *TransparencyCheckpoint, publicKey *PublicKey) error {
	return core.VerifyTransparencyCheckpoint(report, checkpoint, publicKey)
}

func VerifyTransparencyCheckpointWithRevocations(report InventoryReport, revocations *RevocationManifest, checkpoint *TransparencyCheckpoint, publicKey *PublicKey) error {
	return core.VerifyTransparencyCheckpointWithRevocations(report, revocations, checkpoint, publicKey)
}

func BuildTransparencyBundle(report InventoryReport, checkpoint *TransparencyCheckpoint) (TransparencyBundle, error) {
	return core.BuildTransparencyBundle(report, checkpoint)
}

func BuildTransparencyBundleWithRevocations(report InventoryReport, revocations *RevocationManifest, checkpoint *TransparencyCheckpoint) (TransparencyBundle, error) {
	return core.BuildTransparencyBundleWithRevocations(report, revocations, checkpoint)
}

func VerifyTransparencyBundle(bundle TransparencyBundle, publicKey *PublicKey) error {
	return core.VerifyTransparencyBundle(bundle, publicKey)
}

func PublicKeyFingerprint(publicKey []byte) string {
	return core.PublicKeyFingerprint(publicKey)
}

func MerkleRootHex(leaves [][]byte) string {
	return core.MerkleRootHex(leaves)
}

func NewRevocationManifest(now time.Time) RevocationManifest {
	return core.NewRevocationManifest(now)
}

func ParseRevocationSubject(subjectType, subject string) (string, string, error) {
	return core.ParseRevocationSubject(subjectType, subject)
}

func ValidateRevocationManifest(manifest RevocationManifest) error {
	return core.ValidateRevocationManifest(manifest)
}

func RevocationEventID(event RevocationEvent) (string, error) {
	return core.RevocationEventID(event)
}

func ReadRevocationManifest(r io.Reader) (RevocationManifest, error) {
	return core.ReadRevocationManifest(r)
}

func WriteRevocationManifest(w io.Writer, manifest RevocationManifest) error {
	return core.WriteRevocationManifest(w, manifest)
}

func RevocationManifestRoot(manifest RevocationManifest) (string, error) {
	return core.RevocationManifestRoot(manifest)
}

func RevocationManifestDigest(manifest RevocationManifest) (string, error) {
	return core.RevocationManifestDigest(manifest)
}

func InspectTLS(ctx context.Context, target string, opts TLSInspectOptions) (TLSReport, error) {
	return core.InspectTLS(ctx, target, opts)
}

func PublicWeb2029TLSReadinessPolicy() TLSReadinessPolicy {
	return core.PublicWeb2029TLSReadinessPolicy()
}

func ResolveTLSReadinessPolicy(id string) (TLSReadinessPolicy, error) {
	return core.ResolveTLSReadinessPolicy(id)
}

func EvaluateTLSReadiness(report TLSReport, policy TLSReadinessPolicy, now time.Time) TLSReadiness {
	return core.EvaluateTLSReadiness(report, policy, now)
}

func ApplyTLSReadinessPolicy(report *InventoryReport, policyID string, now time.Time) error {
	return core.ApplyTLSReadinessPolicy(report, policyID, now)
}

func BuildReadinessScan(report InventoryReport, now time.Time) ReadinessScan {
	return core.BuildReadinessScan(report, now)
}

func NewMTCLog(now time.Time) MTCLog {
	return core.NewMTCLog(now)
}

func BuildMTCCheckpoint(log MTCLog, now time.Time) (*MTCCheckpoint, error) {
	return core.BuildMTCCheckpoint(log, now)
}

func SignMTCCheckpoint(ctx context.Context, manager interface {
	Sign(context.Context, string, []byte, SignOptions) (*SignatureEnvelope, error)
}, checkpoint *MTCCheckpoint, signKey string) error {
	return core.SignMTCCheckpoint(ctx, manager, checkpoint, signKey)
}

func BuildMTCProof(log MTCLog, leafIndex int, now time.Time) (*MTCProof, error) {
	return core.BuildMTCProof(log, leafIndex, now)
}

func VerifyMTCProof(proof *MTCProof, checkpoint *MTCCheckpoint, publicKey *PublicKey) error {
	return core.VerifyMTCProof(proof, checkpoint, publicKey)
}

func MTCLeafHash(entry MTCLogEntry) (string, error) {
	return core.MTCLeafHash(entry)
}

func NewMTCTreeheadCache(source string, entries []MTCTreeheadEntry, now time.Time) MTCTreeheadCache {
	return core.NewMTCTreeheadCache(source, entries, now)
}

func NewMTCTreeheadEntry(source, logID string, checkpoint MTCCheckpoint, publicKey PublicKey, now time.Time) (MTCTreeheadEntry, error) {
	return core.NewMTCTreeheadEntry(source, logID, checkpoint, publicKey, now)
}

func MTCTreeheadEntryID(entry MTCTreeheadEntry) (string, error) {
	return core.MTCTreeheadEntryID(entry)
}

func VerifyMTCTreeheadCache(cache MTCTreeheadCache) (*MTCTreeheadVerifyResult, error) {
	return core.VerifyMTCTreeheadCache(cache)
}

func ParseMTCTreeheadSource(data []byte, source string, publicKey *PublicKey, logID string, now time.Time) (MTCTreeheadCache, error) {
	return core.ParseMTCTreeheadSource(data, source, publicKey, logID, now)
}

func DefaultMTCTreeheadLogID(source string) string {
	return core.DefaultMTCTreeheadLogID(source)
}
