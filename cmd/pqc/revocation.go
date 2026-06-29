package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	pqc "github.com/helsingin/pqc"
)

const defaultRevocationManifestPath = "revocations.json"

func readOrCreateRevocationManifest(path string) (pqc.RevocationManifest, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return pqc.RevocationManifest{}, fmt.Errorf("revocation manifest path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pqc.NewRevocationManifest(time.Now().UTC()), nil
		}
		return pqc.RevocationManifest{}, err
	}
	return pqc.ReadRevocationManifest(bytes.NewReader(data))
}

func writeRevocationManifestFile(path string, manifest pqc.RevocationManifest) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("revocation manifest path is required")
	}
	if err := pqc.ValidateRevocationManifest(manifest); err != nil {
		return err
	}
	return writeJSONFileAtomic(path, manifest, 0o600)
}
