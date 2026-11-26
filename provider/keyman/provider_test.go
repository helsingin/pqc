//go:build cgo

package keyman_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	keyring "github.com/helsingin/keyman"
	"github.com/helsingin/keyman/pkcs11"
	"github.com/helsingin/pqc"
	"github.com/helsingin/pqc/profile"
	adapter "github.com/helsingin/pqc/provider/keyman"
	"github.com/helsingin/pqc/store/file"
	p11 "github.com/miekg/pkcs11"
)

var profiles = []struct {
	typ       keyring.KeyType
	algorithm pqc.Algorithm
}{
	{keyring.KeyTypeMLDSA65, pqc.AlgorithmMLDSA65},
	{keyring.KeyTypeMLDSA87, pqc.AlgorithmMLDSA87},
	{keyring.KeyTypeSLHDSASHA2192s, pqc.AlgorithmSLHDSASHA2192s},
	{keyring.KeyTypeSLHDSASHA2256s, pqc.AlgorithmSLHDSASHA2256s},
}

func TestProviderRejectsUninitialized(t *testing.T) {
	if _, err := adapter.New(nil); err == nil {
		t.Fatal("nil manager accepted")
	}
	var p *adapter.Provider
	if _, err := p.ExportPublic(t.Context(), "id"); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := p.Sign(t.Context(), "id", nil, pqc.SignOptions{}); err == nil {
		t.Fatal("nil provider accepted")
	}
}

func TestSoftwareProviderEvidence(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p.algorithm), func(t *testing.T) {
			store, err := file.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			manager := pqc.NewManager(store)
			if _, err := manager.Generate(t.Context(), pqc.GenerateRequest{ID: "software", Algorithm: p.algorithm}); err != nil {
				t.Fatal(err)
			}
			public, err := manager.ExportPublic(t.Context(), "software")
			if err != nil {
				t.Fatal(err)
			}
			exerciseEvidence(t, manager, public)
		})
	}
}

func TestTokenProviderEvidence(t *testing.T) {
	if os.Getenv("PKCS11_MODULE_PATH") == "" {
		t.Skip("requires disposable PKCS#11 token; see scripts/test-keyman-provider.sh")
	}
	manager, err := pkcs11.New(pkcs11.Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	provider, err := adapter.New(manager)
	if err != nil {
		t.Fatal(err)
	}
	var offline []func() error
	for _, p := range profiles {
		t.Run(string(p.algorithm), func(t *testing.T) {
			ctx := t.Context()
			key, err := manager.CreateKey(ctx, p.typ, fmt.Sprintf("provider-%d", time.Now().UnixNano()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := manager.DeleteKey(ctx, key.ID); err != nil {
					t.Error(err)
				}
			}()
			public, err := provider.ExportPublic(ctx, key.ID)
			if err != nil {
				t.Fatal(err)
			}
			if public.Algorithm != p.algorithm || public.Version != 1 {
				t.Fatalf("wrong public metadata: %+v", public)
			}
			exerciseOptions(t, provider, public)
			offline = append(offline, exerciseEvidence(t, provider, public)...)
			assertProtected(t, key.ID, 1)
			// A rotation may overlap the adapter's binding/signing steps. Every result
			// must verify against the public key of its reported version.
			results := make(chan *pqc.SignatureEnvelope, 4)
			failures := make(chan error, 1)
			go func() {
				defer close(results)
				for i := 0; i < 4; i++ {
					sig, err := provider.Sign(ctx, key.ID, []byte("overlapping rotation"), pqc.SignOptions{Context: []byte("rotation")})
					if err != nil {
						failures <- err
						return
					}
					results <- sig
				}
			}()
			if _, err := manager.RotateKey(ctx, key.ID); err != nil {
				t.Fatal(err)
			}
			next, err := provider.ExportPublic(ctx, key.ID)
			if err != nil {
				t.Fatal(err)
			}
			if next.Version != 2 || next.CreatedAt.Before(public.CreatedAt) || bytes.Equal(next.PublicKey, public.PublicKey) {
				t.Fatal("invalid rotated public key")
			}
			for sig := range results {
				pub := public
				if sig.KeyVersion == 2 {
					pub = next
				}
				if err := pqc.VerifyWithPublicKey(*pub, []byte("overlapping rotation"), sig); err != nil {
					t.Fatalf("rotation metadata/signature mismatch: %v", err)
				}
			}
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
			offline = append(offline, exerciseEvidence(t, provider, next)...)
			assertProtected(t, key.ID, 1)
			assertProtected(t, key.ID, 2)
			// Historical evidence is independently verifiable even after DeleteKey.
		})
	}
	if _, err := provider.Sign(t.Context(), "absent", nil, pqc.SignOptions{}); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.Sign(cancelled, "absent", nil, pqc.SignOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sign: %v", err)
	}
	unsupported, err := manager.CreateKey(t.Context(), keyring.KeyTypeECDSAP256, "provider-unsupported")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Sign(t.Context(), unsupported.ID, nil, pqc.SignOptions{}); !errors.Is(err, keyring.ErrUnsupportedKeyType) {
		t.Fatalf("unsupported algorithm: %v", err)
	}
	if err := manager.DeleteKey(t.Context(), unsupported.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Sign(t.Context(), "absent", nil, pqc.SignOptions{}); err == nil {
		t.Fatal("closed token accepted")
	}
	for _, verify := range offline {
		if err := verify(); err != nil {
			t.Fatalf("offline verification: %v", err)
		}
	}
}

// Inspect the actual objects after adapter use. The manager owns module
// initialization; this probe opens/closes only an additional read-only session.
func assertProtected(t *testing.T, id string, version int) {
	t.Helper()
	module := p11.New(os.Getenv("PKCS11_MODULE_PATH"))
	if module == nil {
		t.Fatal("load protection probe")
	}
	defer module.Destroy()
	slots, err := module.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots {
		info, err := module.GetTokenInfo(slot)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(info.Label) != os.Getenv("PKCS11_TOKEN_LABEL") {
			continue
		}
		session, err := module.OpenSession(slot, p11.CKF_SERIAL_SESSION)
		if err != nil {
			t.Fatal(err)
		}
		defer module.CloseSession(session)
		attrs := []*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY), p11.NewAttribute(p11.CKA_LABEL, fmt.Sprintf("%s:v%d:private", id, version))}
		if err := module.FindObjectsInit(session, attrs); err != nil {
			t.Fatal(err)
		}
		objects, _, findErr := module.FindObjects(session, 2)
		finalErr := module.FindObjectsFinal(session)
		if findErr != nil || finalErr != nil || len(objects) != 1 {
			t.Fatalf("private object lookup: %v %v count=%d", findErr, finalErr, len(objects))
		}
		_, err = module.GetAttributeValue(session, objects[0], []*p11.Attribute{p11.NewAttribute(p11.CKA_VALUE, nil)})
		if !errors.Is(err, p11.Error(p11.CKR_ATTRIBUTE_SENSITIVE)) {
			t.Fatalf("private material readable: %v", err)
		}
		flags, err := module.GetAttributeValue(session, objects[0], []*p11.Attribute{p11.NewAttribute(p11.CKA_ALWAYS_SENSITIVE, nil), p11.NewAttribute(p11.CKA_NEVER_EXTRACTABLE, nil)})
		if err != nil || len(flags) != 2 || !bytes.Equal(flags[0].Value, []byte{1}) || !bytes.Equal(flags[1].Value, []byte{1}) {
			t.Fatalf("private protection flags: %v", err)
		}
		return
	}
	t.Fatal("token not found by protection probe")
}

func exerciseOptions(t *testing.T, provider pqc.SigningProvider, public *pqc.PublicKey) {
	t.Helper()
	message := []byte("provider signing options")
	for _, ctx := range [][]byte{nil, []byte("domain separation"), bytes.Repeat([]byte{0xa5}, 255)} {
		opts := pqc.SignOptions{Context: ctx}
		a, err := provider.Sign(t.Context(), public.ID, message, opts)
		if err != nil {
			t.Fatal(err)
		}
		b, err := provider.Sign(t.Context(), public.ID, message, opts)
		if err != nil || !bytes.Equal(a.Signature, b.Signature) {
			t.Fatalf("deterministic mode: %v", err)
		}
		if !bytes.Equal(a.Context, ctx) {
			t.Fatal("context lost")
		}
		if err := pqc.VerifyWithPublicKey(*public, message, a); err != nil {
			t.Fatal(err)
		}
		opts.Randomized = true
		b, err = provider.Sign(t.Context(), public.ID, message, opts)
		if err != nil || bytes.Equal(a.Signature, b.Signature) {
			t.Fatalf("randomized mode: %v", err)
		}
		if err := pqc.VerifyWithPublicKey(*public, message, b); err != nil {
			t.Fatal(err)
		}
	}
	if sig, err := provider.Sign(t.Context(), public.ID, message, pqc.SignOptions{Context: make([]byte, 256)}); !errors.Is(err, pkcs11.ErrUnsupportedPQOperation) || sig != nil {
		t.Fatalf("overlong context: %v", err)
	}
}

// Exercise the same four callers for both providers, retaining only public
// verification closures. Each verifier must also reject tampered signatures,
// wrong signing contexts and wrong key versions.
func exerciseEvidence(t *testing.T, signer pqc.SigningProvider, public *pqc.PublicKey) []func() error {
	t.Helper()
	ctx, now := t.Context(), time.Now().UTC()
	var offline []func() error
	check := func(signature *pqc.SignatureEnvelope, verify func() error) {
		t.Helper()
		if signature == nil || signature.Schema != pqc.SignatureSchema || signature.KeyID != public.ID || signature.KeyVersion != public.Version || signature.Algorithm != public.Algorithm || len(signature.Context) == 0 {
			t.Fatal("invalid signature envelope")
		}
		if err := verify(); err != nil {
			t.Fatal(err)
		}
		originalContext := signature.Context
		signature.Context = []byte("wrong")
		if err := verify(); err == nil {
			t.Fatal("wrong context accepted")
		}
		signature.Context = originalContext
		signature.Signature[0] ^= 1
		if err := verify(); err == nil {
			t.Fatal("corrupt signature accepted")
		}
		signature.Signature[0] ^= 1
		signature.KeyVersion++
		if err := verify(); err == nil {
			t.Fatal("wrong version accepted")
		}
		signature.KeyVersion--
		offline = append(offline, verify)
	}
	artifact := &profile.IssuedArtifact{Schema: profile.ArtifactSchema, Profile: "provider-test", Type: "evidence", IssuedAt: now, Subject: profile.Subject{CommonName: "test"}}
	if err := profile.SignArtifact(ctx, signer, public.ID, artifact); err != nil {
		t.Fatal(err)
	}
	check(artifact.Signature, func() error { return profile.VerifyArtifactSignature(artifact, public) })
	const log = `{"operation":"sign","key_id":"test","success":true}` + "\n"
	audit, err := pqc.BuildAuditCheckpoint(strings.NewReader(log), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqc.SignAuditCheckpoint(ctx, signer, audit, public.ID); err != nil {
		t.Fatal(err)
	}
	check(audit.Signature, func() error { return pqc.VerifyAuditCheckpoint(strings.NewReader(log), audit, public) })
	inventory := pqc.BuildInventoryReport([]pqc.KeyMetadata{{ID: public.ID, Version: public.Version, Algorithm: public.Algorithm, Use: pqc.KeyUseSignature, CreatedAt: public.CreatedAt}}, nil, now)
	transparency, err := pqc.BuildTransparencyCheckpoint(inventory, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqc.SignTransparencyCheckpoint(ctx, signer, transparency, public.ID); err != nil {
		t.Fatal(err)
	}
	check(transparency.Signature, func() error { return pqc.VerifyTransparencyCheckpoint(inventory, transparency, public) })
	tree := pqc.NewMTCLog(now)
	if _, err := tree.Add("example.invalid", pqc.PublicKeyFingerprint(public.PublicKey), nil, now); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := pqc.BuildMTCCheckpoint(tree, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqc.SignMTCCheckpoint(ctx, signer, checkpoint, public.ID); err != nil {
		t.Fatal(err)
	}
	proof, err := pqc.BuildMTCProof(tree, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	check(checkpoint.Signature, func() error { return pqc.VerifyMTCProof(proof, checkpoint, public) })
	return offline
}
