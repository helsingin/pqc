package core

import (
	"fmt"
	"strings"
)

// Algorithm identifies a supported post-quantum primitive.
type Algorithm string

const (
	AlgorithmMLKEM768 Algorithm = "ML-KEM-768"
	AlgorithmMLDSA65  Algorithm = "ML-DSA-65"
	AlgorithmMLDSA87  Algorithm = "ML-DSA-87"
)

// KeyUse describes what an algorithm can be used for.
type KeyUse string

const (
	KeyUseKEM       KeyUse = "kem"
	KeyUseSignature KeyUse = "signature"
)

// ParseAlgorithm accepts canonical names and common aliases used by earlier
// PQC drafts and libraries.
func ParseAlgorithm(value string) (Algorithm, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	switch normalized {
	case "ml-kem-768", "mlkem768", "kyber768", "kyber-768":
		return AlgorithmMLKEM768, nil
	case "ml-dsa-65", "mldsa65", "dilithium3", "dilithium-3":
		return AlgorithmMLDSA65, nil
	case "ml-dsa-87", "mldsa87", "dilithium5", "dilithium-5":
		return AlgorithmMLDSA87, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", value)
	}
}

func (a Algorithm) Use() (KeyUse, error) {
	switch a {
	case AlgorithmMLKEM768:
		return KeyUseKEM, nil
	case AlgorithmMLDSA65, AlgorithmMLDSA87:
		return KeyUseSignature, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", a)
	}
}

func (a Algorithm) Validate() error {
	_, err := a.Use()
	return err
}
