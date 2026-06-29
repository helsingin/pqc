package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	pqc "github.com/helsingin/pqc"
)

const defaultMTCLogPath = "mtc-log.json"
const defaultMTCTreeheadCacheDir = "treeheads"
const defaultMTCTreeheadExportDir = "openssl-treeheads"
const mtcTreeheadManifestName = "manifest.json"

func (a *app) runMTC(args []string) int {
	if len(args) == 0 {
		a.printMTCUsage()
		return 2
	}
	switch args[0] {
	case "log":
		if len(args) == 1 {
			a.printMTCUsage()
			return 2
		}
		switch args[1] {
		case "init":
			return a.runMTCLogInit(args[2:])
		default:
			return a.failUsage(fmt.Errorf("unknown mtc log command %q", args[1]), a.printMTCUsage)
		}
	case "issue":
		return a.runMTCIssue(args[1:])
	case "revoke":
		return a.runMTCRevoke(args[1:])
	case "checkpoint":
		return a.runMTCCheckpoint(args[1:])
	case "prove":
		return a.runMTCProve(args[1:])
	case "verify":
		return a.runMTCVerify(args[1:])
	case "treeheads":
		return a.runMTCTreeheads(args[1:])
	case "help", "-h", "--help":
		a.printMTCUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown mtc command %q", args[0]), a.printMTCUsage)
	}
}

func (a *app) runMTCLogInit(args []string) int {
	fs := a.flagSet("pqc mtc log init")
	logPath := fs.String("log", defaultMTCLogPath, "MTC log JSON path")
	force := fs.Bool("force", false, "overwrite an existing log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc log init does not take arguments"), a.printMTCUsage)
	}
	if _, err := os.Stat(*logPath); err == nil && !*force {
		return a.fail(fmt.Errorf("%s already exists; use --force to overwrite", *logPath))
	} else if err != nil && !os.IsNotExist(err) {
		return a.fail(err)
	}
	log := pqc.NewMTCLog(time.Now().UTC())
	if err := writeMTCLogFile(*logPath, log); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, log)
}

func (a *app) runMTCIssue(args []string) int {
	fs := a.flagSet("pqc mtc issue")
	logPath := fs.String("log", defaultMTCLogPath, "MTC log JSON path")
	subject := fs.String("subject", "", "MTC subject")
	publicKeyPath := fs.String("public-key", "", "public key or fingerprint JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *publicKeyPath == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc issue requires --subject and --public-key"), a.printMTCUsage)
	}
	log, err := readMTCLogFile(*logPath)
	if err != nil {
		return a.fail(err)
	}
	fingerprint, err := readPublicKeyFingerprint(*publicKeyPath)
	if err != nil {
		return a.fail(err)
	}
	entry, err := log.Add(*subject, fingerprint, nil, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if err := writeMTCLogFile(*logPath, log); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, entry)
}

func (a *app) runMTCRevoke(args []string) int {
	fs := a.flagSet("pqc mtc revoke")
	logPath := fs.String("log", defaultMTCLogPath, "MTC log JSON path")
	leaf := fs.Int("index", -1, "MTC leaf index to revoke")
	reason := fs.String("reason", "", "revocation reason")
	revocationPath := fs.String("revocations", defaultRevocationManifestPath, "revocation manifest path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *leaf < 0 || *reason == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc revoke requires --index and --reason"), a.printMTCUsage)
	}
	log, err := readMTCLogFile(*logPath)
	if err != nil {
		return a.fail(err)
	}
	if *leaf >= len(log.Entries) {
		return a.fail(fmt.Errorf("MTC leaf index %d out of range", *leaf))
	}
	entry := log.Entries[*leaf]
	manifest, err := readOrCreateRevocationManifest(*revocationPath)
	if err != nil {
		return a.fail(err)
	}
	event, err := manifest.Add("mtc-leaf", fmt.Sprint(*leaf), *reason, map[string]any{
		"mtc_leaf_hash":          entry.LeafHash,
		"mtc_leaf_index":         *leaf,
		"mtc_log":                *logPath,
		"mtc_subject":            entry.Subject,
		"public_key_fingerprint": entry.PublicKeyFingerprint,
	}, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if err := writeRevocationManifestFile(*revocationPath, manifest); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, event)
}

func (a *app) runMTCCheckpoint(args []string) int {
	fs := a.flagSet("pqc mtc checkpoint")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	logPath := fs.String("log", defaultMTCLogPath, "MTC log JSON path")
	signKey := fs.String("sign-key", "", "ML-DSA key id used to sign the checkpoint")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *signKey == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc checkpoint requires --sign-key"), a.printMTCUsage)
	}
	log, err := readMTCLogFile(*logPath)
	if err != nil {
		return a.fail(err)
	}
	checkpoint, err := pqc.BuildMTCCheckpoint(log, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	if err := pqc.SignMTCCheckpoint(a.ctx, client, checkpoint, *signKey); err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, checkpoint)
}

func (a *app) runMTCProve(args []string) int {
	fs := a.flagSet("pqc mtc prove")
	logPath := fs.String("log", defaultMTCLogPath, "MTC log JSON path")
	leaf := fs.Int("leaf", -1, "MTC leaf index")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *leaf < 0 || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc prove requires --leaf INDEX"), a.printMTCUsage)
	}
	log, err := readMTCLogFile(*logPath)
	if err != nil {
		return a.fail(err)
	}
	proof, err := pqc.BuildMTCProof(log, *leaf, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, proof)
}

func (a *app) runMTCVerify(args []string) int {
	fs := a.flagSet("pqc mtc verify")
	var clientOpts clientOptions
	registerClientAccessFlags(fs, &clientOpts)
	proofPath := fs.String("proof", "", "MTC inclusion proof JSON")
	checkpointPath := fs.String("checkpoint", "", "MTC checkpoint JSON")
	publicKeyPath := fs.String("public-key", "", "exported checkpoint signer public key JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *proofPath == "" || *checkpointPath == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc verify requires --proof and --checkpoint"), a.printMTCUsage)
	}
	var proof pqc.MTCProof
	if err := readJSONFile(*proofPath, &proof); err != nil {
		return a.fail(err)
	}
	var checkpoint pqc.MTCCheckpoint
	if err := readJSONFile(*checkpointPath, &checkpoint); err != nil {
		return a.fail(err)
	}
	publicKey, err := loadMTCPublicKey(a, fs, clientOpts, *publicKeyPath, checkpoint.Signature)
	if err != nil {
		return a.fail(err)
	}
	if err := pqc.VerifyMTCProof(&proof, &checkpoint, publicKey); err != nil {
		return a.fail(err)
	}
	_, _ = fmt.Fprintln(a.stdout, "OK")
	return 0
}

func (a *app) runMTCTreeheads(args []string) int {
	if len(args) == 0 {
		a.printMTCTreeheadsUsage()
		return 2
	}
	switch args[0] {
	case "fetch":
		return a.runMTCTreeheadsFetch(args[1:])
	case "verify":
		return a.runMTCTreeheadsVerify(args[1:])
	case "export":
		return a.runMTCTreeheadsExport(args[1:])
	case "help", "-h", "--help":
		a.printMTCTreeheadsUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown mtc treeheads command %q", args[0]), a.printMTCTreeheadsUsage)
	}
}

func (a *app) runMTCTreeheadsFetch(args []string) int {
	fs := a.flagSet("pqc mtc treeheads fetch")
	source := fs.String("source", "", "MTC treehead source URL")
	outDir := fs.String("out", defaultMTCTreeheadCacheDir, "treehead cache output directory")
	publicKeyPath := fs.String("public-key", "", "signer public key for a single-checkpoint source")
	logID := fs.String("log-id", "", "log id for a single-checkpoint source")
	timeout := fs.Duration("timeout", 10*time.Second, "fetch timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("mtc treeheads fetch requires --source URL"), a.printMTCTreeheadsUsage)
	}
	var publicKey *pqc.PublicKey
	if *publicKeyPath != "" {
		loaded, err := readPublicKeyFile(*publicKeyPath)
		if err != nil {
			return a.fail(err)
		}
		publicKey = loaded
	}
	data, err := fetchMTCTreeheadSource(a.ctx, *source, *timeout)
	if err != nil {
		return a.fail(err)
	}
	cache, err := pqc.ParseMTCTreeheadSource(data, *source, publicKey, *logID, time.Now().UTC())
	if err != nil {
		return a.fail(err)
	}
	if _, err := pqc.VerifyMTCTreeheadCache(cache); err != nil {
		return a.fail(err)
	}
	if err := writeMTCTreeheadCacheDir(*outDir, cache); err != nil {
		return a.fail(err)
	}
	_, _ = fmt.Fprintf(a.stdout, "fetched_treeheads: %d\ncache: %s\n", len(cache.Treeheads), *outDir)
	return 0
}

func (a *app) runMTCTreeheadsVerify(args []string) int {
	fs := a.flagSet("pqc mtc treeheads verify")
	jsonOut := fs.Bool("json", false, "write JSON verification result")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return a.failUsage(fmt.Errorf("mtc treeheads verify requires CACHE_DIR"), a.printMTCTreeheadsUsage)
	}
	cache, err := readMTCTreeheadCachePath(fs.Arg(0))
	if err != nil {
		if *jsonOut {
			return writeMTCTreeheadVerifyErrorJSON(a, "cache", err)
		}
		return a.fail(err)
	}
	result, err := pqc.VerifyMTCTreeheadCache(cache)
	if *jsonOut {
		if code := writeJSON(a.stdout, a.stderr, result); code != 0 {
			return code
		}
		if err != nil {
			return 1
		}
		return 0
	}
	if err != nil {
		return a.fail(err)
	}
	_, _ = fmt.Fprintf(a.stdout, "OK verified_treeheads=%d\n", result.Verified)
	return 0
}

func writeMTCTreeheadVerifyErrorJSON(a *app, subject string, err error) int {
	result := pqc.MTCTreeheadVerifyResult{
		OK: false,
		Findings: []pqc.MTCTreeheadFinding{{
			Severity: "error",
			Subject:  subject,
			Message:  err.Error(),
		}},
	}
	if code := writeJSON(a.stdout, a.stderr, result); code != 0 {
		return code
	}
	return 1
}

func (a *app) runMTCTreeheadsExport(args []string) int {
	fs := a.flagSet("pqc mtc treeheads export")
	format := fs.String("format", "openssl-dir", "export format")
	cachePath := fs.String("cache", defaultMTCTreeheadCacheDir, "treehead cache directory")
	outDir := fs.String("out", defaultMTCTreeheadExportDir, "export output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		return a.failUsage(fmt.Errorf("mtc treeheads export takes at most one CACHE_DIR argument"), a.printMTCTreeheadsUsage)
	}
	if fs.NArg() == 1 {
		*cachePath = fs.Arg(0)
	}
	if *format != "openssl-dir" {
		return a.fail(fmt.Errorf("unsupported mtc treeheads export format %q", *format))
	}
	cache, err := readMTCTreeheadCachePath(*cachePath)
	if err != nil {
		return a.fail(err)
	}
	if _, err := pqc.VerifyMTCTreeheadCache(cache); err != nil {
		return a.fail(err)
	}
	if err := exportMTCTreeheadsOpenSSLDir(*outDir, *cachePath, cache); err != nil {
		return a.fail(err)
	}
	_, _ = fmt.Fprintf(a.stdout, "exported_treeheads: %d\nformat: %s\nout: %s\n", len(cache.Treeheads), *format, *outDir)
	return 0
}

func readMTCLogFile(path string) (pqc.MTCLog, error) {
	var log pqc.MTCLog
	if err := readJSONFile(path, &log); err != nil {
		return pqc.MTCLog{}, err
	}
	return log, nil
}

func writeMTCLogFile(path string, log pqc.MTCLog) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pqc-mtc-log-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func writeMTCTreeheadCacheDir(path string, cache pqc.MTCTreeheadCache) error {
	treeheadsDir := filepath.Join(path, "treeheads")
	if err := os.RemoveAll(treeheadsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(treeheadsDir, 0o755); err != nil {
		return err
	}
	if err := writeJSONFileAtomic(filepath.Join(path, mtcTreeheadManifestName), cache, 0o644); err != nil {
		return err
	}
	for _, entry := range cache.Treeheads {
		if err := writeJSONFileAtomic(filepath.Join(path, "treeheads", safeTreeheadID(entry.ID)+".json"), entry, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func readMTCTreeheadCachePath(path string) (pqc.MTCTreeheadCache, error) {
	info, err := os.Stat(path)
	if err != nil {
		return pqc.MTCTreeheadCache{}, err
	}
	if info.IsDir() {
		cache, err := readMTCTreeheadCacheFile(filepath.Join(path, mtcTreeheadManifestName))
		if err != nil {
			return pqc.MTCTreeheadCache{}, err
		}
		if err := verifyMTCTreeheadCacheFiles(path, cache); err != nil {
			return pqc.MTCTreeheadCache{}, err
		}
		return cache, nil
	}
	return readMTCTreeheadCacheFile(path)
}

func readMTCTreeheadCacheFile(path string) (pqc.MTCTreeheadCache, error) {
	var cache pqc.MTCTreeheadCache
	if err := readJSONFile(path, &cache); err != nil {
		return pqc.MTCTreeheadCache{}, err
	}
	return cache, nil
}

func verifyMTCTreeheadCacheFiles(path string, cache pqc.MTCTreeheadCache) error {
	treeheadsDir := filepath.Join(path, "treeheads")
	entries, err := os.ReadDir(treeheadsDir)
	if err != nil {
		return err
	}
	expected := map[string]pqc.MTCTreeheadEntry{}
	for _, treehead := range cache.Treeheads {
		expected[safeTreeheadID(treehead.ID)+".json"] = treehead
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			return fmt.Errorf("unexpected directory in MTC treehead cache: %s", filepath.Join(treeheadsDir, name))
		}
		if !strings.HasSuffix(name, ".json") {
			return fmt.Errorf("unexpected file in MTC treehead cache: %s", filepath.Join(treeheadsDir, name))
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("unexpected treehead cache file: %s", filepath.Join(treeheadsDir, name))
		}
		var got pqc.MTCTreeheadEntry
		if err := readJSONFile(filepath.Join(treeheadsDir, name), &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("treehead cache file does not match manifest: %s", filepath.Join(treeheadsDir, name))
		}
		seen[name] = true
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("missing treehead cache file: %s", filepath.Join(treeheadsDir, name))
		}
	}
	return nil
}

func exportMTCTreeheadsOpenSSLDir(outDir, cachePath string, cache pqc.MTCTreeheadCache) error {
	if err := os.RemoveAll(filepath.Join(outDir, "treeheads")); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(outDir, "public-keys")); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(outDir, "treeheads"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(outDir, "public-keys"), 0o755); err != nil {
		return err
	}
	type exportedTreehead struct {
		ID                   string    `json:"id"`
		LogID                string    `json:"log_id"`
		TreeSize             int       `json:"tree_size"`
		MerkleRoot           string    `json:"merkle_root"`
		GeneratedAt          time.Time `json:"generated_at"`
		SignerKeyID          string    `json:"signer_key_id"`
		SignerPublicKeyFile  string    `json:"signer_public_key_file"`
		TreeheadFile         string    `json:"treehead_file"`
		PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	}
	index := struct {
		Schema     string             `json:"schema"`
		Format     string             `json:"format"`
		Cache      string             `json:"cache"`
		ExportedAt time.Time          `json:"exported_at"`
		Treeheads  []exportedTreehead `json:"treeheads"`
	}{
		Schema:     "pqc.mtc-treeheads.openssl-dir.v1",
		Format:     "openssl-dir",
		Cache:      cachePath,
		ExportedAt: time.Now().UTC(),
	}
	for _, entry := range cache.Treeheads {
		logDir := filepath.Join("treeheads", safePathComponent(entry.LogID))
		if err := os.MkdirAll(filepath.Join(outDir, logDir), 0o755); err != nil {
			return err
		}
		treeheadRel := filepath.Join(logDir, fmt.Sprintf("%d-%s.json", entry.Checkpoint.TreeSize, shortTreeheadRoot(entry.Checkpoint.MerkleRoot)))
		publicKeyFingerprint := pqc.PublicKeyFingerprint(entry.PublicKey.PublicKey)
		publicKeyRel := filepath.Join("public-keys", safePathComponent(publicKeyFingerprint)+".json")
		if err := writeJSONFileAtomic(filepath.Join(outDir, treeheadRel), entry, 0o644); err != nil {
			return err
		}
		if err := writeJSONFileAtomic(filepath.Join(outDir, publicKeyRel), entry.PublicKey, 0o644); err != nil {
			return err
		}
		index.Treeheads = append(index.Treeheads, exportedTreehead{
			ID:                   entry.ID,
			LogID:                entry.LogID,
			TreeSize:             entry.Checkpoint.TreeSize,
			MerkleRoot:           entry.Checkpoint.MerkleRoot,
			GeneratedAt:          entry.Checkpoint.GeneratedAt,
			SignerKeyID:          entry.Checkpoint.Signature.KeyID,
			SignerPublicKeyFile:  filepath.ToSlash(publicKeyRel),
			TreeheadFile:         filepath.ToSlash(treeheadRel),
			PublicKeyFingerprint: publicKeyFingerprint,
		})
	}
	readme := []byte("pqc experimental MTC treehead cache export\n\nThis directory is not an OpenSSL trust store. It mirrors an /etc/ssl-style directory layout for non-browser clients that need signed MTC treehead JSON and signer public keys.\n")
	if err := os.WriteFile(filepath.Join(outDir, "README.pqc-treeheads"), readme, 0o644); err != nil {
		return err
	}
	return writeJSONFileAtomic(filepath.Join(outDir, "index.json"), index, 0o644)
}

func writeJSONFileAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pqc-json-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func fetchMTCTreeheadSource(ctx context.Context, source string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch %s: HTTP %s", source, resp.Status)
	}
	const maxTreeheadSourceBytes = 16 * 1024 * 1024
	limited := &io.LimitedReader{R: resp.Body, N: maxTreeheadSourceBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxTreeheadSourceBytes {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", source, maxTreeheadSourceBytes)
	}
	return data, nil
}

func readJSONFile(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeStrict(data, value)
}

func readPublicKeyFile(path string) (*pqc.PublicKey, error) {
	var publicKey pqc.PublicKey
	if err := readJSONFile(path, &publicKey); err != nil {
		return nil, err
	}
	return &publicKey, nil
}

func readPublicKeyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var publicKey pqc.PublicKey
	if err := decodeStrict(data, &publicKey); err == nil && len(publicKey.PublicKey) != 0 {
		return pqc.PublicKeyFingerprint(publicKey.PublicKey), nil
	}
	var doc struct {
		PublicKeyFingerprint string `json:"public_key_fingerprint"`
		Fingerprint          string `json:"fingerprint"`
		FingerprintSHA256    string `json:"fingerprint_sha256"`
	}
	if err := json.Unmarshal(data, &doc); err == nil {
		for _, value := range []string{doc.PublicKeyFingerprint, doc.Fingerprint, doc.FingerprintSHA256} {
			if value != "" {
				return normalizeFingerprint(value)
			}
		}
	}
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		return normalizeFingerprint(value)
	}
	return normalizeFingerprint(string(data))
}

func normalizeFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if value == "" {
		return "", fmt.Errorf("public key fingerprint is empty")
	}
	if strings.HasPrefix(strings.ToLower(value), "sha256:") {
		value = "sha256:" + strings.TrimSpace(value[len("sha256:"):])
	} else {
		value = "sha256:" + value
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != 64 {
		return "", fmt.Errorf("public key fingerprint must be sha256:HEX")
	}
	for _, ch := range hexPart {
		if !strings.ContainsRune("0123456789abcdefABCDEF", ch) {
			return "", fmt.Errorf("public key fingerprint must be sha256:HEX")
		}
	}
	return "sha256:" + strings.ToLower(hexPart), nil
}

func loadMTCPublicKey(a *app, fs *flag.FlagSet, opts clientOptions, publicKeyPath string, signature *pqc.SignatureEnvelope) (*pqc.PublicKey, error) {
	if publicKeyPath != "" {
		data, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		var publicKey pqc.PublicKey
		if err := decodeStrict(data, &publicKey); err != nil {
			return nil, err
		}
		return &publicKey, nil
	}
	if signature == nil {
		return nil, nil
	}
	client, err := openCommandClient(fs, opts)
	if err != nil {
		return nil, err
	}
	return publicKeyForSignature(a.ctx, client, signature)
}

func safeTreeheadID(id string) string {
	return safePathComponent(strings.TrimPrefix(id, "sha256:"))
}

func safePathComponent(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '.', ch == '-', ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "unknown"
	}
	return out
}

func shortTreeheadRoot(root string) string {
	if len(root) <= 16 {
		return root
	}
	return root[:16]
}

func (a *app) printMTCUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc mtc log init [--log mtc-log.json] [--force]
  pqc mtc issue --subject NAME --public-key public.json [--log mtc-log.json]
  pqc mtc revoke --index INDEX --reason REASON [--log mtc-log.json] [--revocations revocations.json]
  pqc mtc checkpoint --sign-key KEY [--log mtc-log.json] [manager flags]
  pqc mtc prove --leaf INDEX [--log mtc-log.json]
  pqc mtc verify --proof proof.json --checkpoint checkpoint.json [--public-key public.json] [manager access flags]
  pqc mtc treeheads fetch --source URL [--out ./treeheads]
  pqc mtc treeheads verify ./treeheads
  pqc mtc treeheads export --format openssl-dir [--cache ./treeheads] [--out ./openssl-treeheads]
`)
}

func (a *app) printMTCTreeheadsUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc mtc treeheads fetch --source URL [--out ./treeheads]
  pqc mtc treeheads fetch --source URL --public-key public.json [--log-id LOG] [--out ./treeheads]
  pqc mtc treeheads verify [--json] ./treeheads
  pqc mtc treeheads export --format openssl-dir [--cache ./treeheads] [--out ./openssl-treeheads]
`)
}
