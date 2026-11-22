package core_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"testing"

	"github.com/helsingin/pqc"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestMLKEM768Interop(t *testing.T) {
	// Both implementations generate the key pair from the same FIPS 203 (d, z).
	var seed [mlkem.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	goKey, err := mlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	store, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	generator := pqc.NewManager(store, pqc.WithRand(bytes.NewReader(seed[:])))
	meta, err := generator.Generate(t.Context(), pqc.GenerateRequest{ID: "interop", Algorithm: pqc.AlgorithmMLKEM768})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(meta.PublicKey, goKey.EncapsulationKey().Bytes()) {
		t.Error("public key differs from Go ML-KEM-768 for the same seed")
	}
	manager := pqc.NewManager(store)
	message, aad := []byte("interoperable envelope"), []byte("recipient context")
	env, err := manager.Encrypt(t.Context(), "interop", message, pqc.EncryptOptions{AAD: aad})
	if err != nil {
		t.Fatal(err)
	}
	aead := func(t *testing.T, secret []byte) cipher.AEAD {
		t.Helper()
		key, err := hkdf.Key(sha256.New, secret, env.Salt, "pqc:pqc.envelope.v1:ML-KEM-768:interop:1:AES-256-GCM", 32)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return gcm
	}
	t.Run("pqc to Go", func(t *testing.T) {
		secret, err := goKey.Decapsulate(env.EncapsulatedKey)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := aead(t, secret).Open(nil, env.Nonce, env.Ciphertext, aad)
		if err != nil || !bytes.Equal(opened, message) {
			t.Fatalf("Go could not open pqc envelope: %v", err)
		}
	})
	t.Run("Go to pqc", func(t *testing.T) {
		pub, err := mlkem.NewEncapsulationKey768(meta.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		secret, capsule := pub.Encapsulate()
		reply := *env
		reply.EncapsulatedKey = capsule
		reply.Ciphertext = aead(t, secret).Seal(nil, reply.Nonce, message, aad)
		opened, err := manager.Decrypt(t.Context(), &reply, pqc.EncryptOptions{AAD: aad})
		if err != nil || !bytes.Equal(opened, message) {
			t.Fatalf("pqc could not open Go envelope: %v", err)
		}
	})
}
