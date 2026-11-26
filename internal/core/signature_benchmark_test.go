package core

import (
	"encoding/json"
	"testing"
)

// Compare the same 1 KiB artifact through the public manager operations, using
// an in-memory store so filesystem/encrypted-store costs do not dominate.
func BenchmarkSignatureProfiles(b *testing.B) {
	for _, algorithm := range []Algorithm{AlgorithmMLDSA65, AlgorithmMLDSA87, AlgorithmSLHDSASHA2192s, AlgorithmSLHDSASHA2256s} {
		b.Run(string(algorithm), func(b *testing.B) {
			m := NewManager(newMemoryStore())
			ctx := b.Context()
			meta, err := m.Generate(ctx, GenerateRequest{ID: "bench", Algorithm: algorithm})
			if err != nil {
				b.Fatal(err)
			}
			message := make([]byte, 1024)
			opts := SignOptions{Context: []byte("pqc.benchmark.v1")}
			sig, err := m.Sign(ctx, "bench", message, opts)
			if err != nil {
				b.Fatal(err)
			}
			encoded, err := json.Marshal(sig)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("keygen", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, _, err := generateKeyPair(algorithm, m.rand); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("sign", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := m.Sign(ctx, "bench", message, opts); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(len(sig.Signature)), "signature-B")
				b.ReportMetric(float64(len(meta.PublicKey)), "public-key-B")
				b.ReportMetric(float64(len(encoded)), "envelope-B")
			})
			b.Run("verify", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := m.Verify(ctx, message, sig); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
