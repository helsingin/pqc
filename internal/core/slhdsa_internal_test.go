package core

import (
	"crypto/rand"
	"testing"
)

func TestSLHDSAMalformedPrivateKeys(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmSLHDSASHA2192s, AlgorithmSLHDSASHA2256s} {
		t.Run(string(algorithm), func(t *testing.T) {
			id, ok := slhDSAID(algorithm)
			if !ok {
				t.Fatal("missing algorithm")
			}
			for _, n := range []int{0, id.Scheme().PrivateKeySize() - 1, id.Scheme().PrivateKeySize() + 1} {
				record := KeyRecord{Algorithm: algorithm, PrivateKey: make([]byte, n)}
				if _, err := signRecord(record, nil, SignOptions{}, rand.Reader); err == nil {
					t.Fatalf("accepted private key length %d", n)
				}
			}
		})
	}
}

func TestSLHDSAReadinessInventory(t *testing.T) {
	summary := summarizeLocalKeys([]InventoryEntry{
		{Algorithm: AlgorithmSLHDSASHA2192s, Use: KeyUseSignature},
		{Algorithm: AlgorithmSLHDSASHA2256s, Use: KeyUseSignature},
	})
	if summary.Total != 2 || summary.PQSignatures != 2 || summary.PQKEM != 0 {
		t.Fatalf("incorrect SLH-DSA inventory: %+v", summary)
	}
}
