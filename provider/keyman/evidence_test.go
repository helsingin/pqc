//go:build cgo

package keyman_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/helsingin/keyman/pkcs11"
	"github.com/helsingin/pqc"
	"github.com/helsingin/pqc/evidence"
	adapter "github.com/helsingin/pqc/provider/keyman"
)

func TestTokenMultipleSignatureEvidence(t *testing.T) {
	if os.Getenv("PKCS11_MODULE_PATH") == "" {
		t.Skip("requires disposable token")
	}
	for _, indices := range [][2]int{{0, 2}, {1, 3}} {
		t.Run(string(profiles[indices[0]].algorithm), func(t *testing.T) {
			manager, err := pkcs11.New(pkcs11.Config{ModulePath: os.Getenv("PKCS11_MODULE_PATH"), TokenLabel: os.Getenv("PKCS11_TOKEN_LABEL"), PIN: os.Getenv("PKCS11_PIN")})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			provider, err := adapter.New(manager)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			policy := evidence.Policy{Schema: evidence.PolicySchema, ID: "token-dual", Version: 1, Purpose: "release", Context: "integration", NotBefore: now.Unix() - 1, NotAfter: now.Unix() + 3600}
			var keys []pqc.PublicKey
			for _, index := range indices {
				id := fmt.Sprintf("m2-dual-%d-%d", now.UnixNano(), index)
				if _, err := manager.CreateKey(t.Context(), profiles[index].typ, id); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := manager.DeleteKey(t.Context(), id); err != nil {
						t.Error(err)
					}
				}()
				public, err := provider.ExportPublic(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				ref, err := evidence.KeyReference(*public)
				if err != nil {
					t.Fatal(err)
				}
				policy.Signers = append(policy.Signers, ref)
				keys = append(keys, *public)
			}
			payload := []byte("dual-family protected evidence")
			statement, err := evidence.NewStatement(policy, payload, "text/plain", now, nil)
			if err != nil {
				t.Fatal(err)
			}
			document, err := evidence.Sign(t.Context(), statement, []pqc.SigningProvider{provider, provider}, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := evidence.Verify(document, payload, policy, keys, now); err != nil {
				t.Fatal(err)
			}
			stripped := *document
			stripped.Signatures = stripped.Signatures[:1]
			if err := evidence.Verify(&stripped, payload, policy, keys, now); err == nil {
				t.Fatal("token signature stripping accepted")
			}
			// Even explicitly trusting a new weaker policy cannot transplant signatures
			// that originally committed to the two-signer policy.
			weaker := policy
			weaker.Signers = weaker.Signers[:1]
			stripped.Statement.Policy = weaker
			if err := evidence.Verify(&stripped, payload, weaker, keys[:1], now); err == nil {
				t.Fatal("token policy downgrade accepted")
			}
			for _, key := range keys {
				assertProtected(t, key.ID, key.Version)
			}
		})
	}
}
