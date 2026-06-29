package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pqc "github.com/helsingin/pqc"
	filestore "github.com/helsingin/pqc/store/file"
)

func TestCLISmokeEncryptDecryptSignVerify(t *testing.T) {
	storeDir := t.TempDir()
	messageFile := filepath.Join(t.TempDir(), "message.txt")
	if err := os.WriteFile(messageFile, []byte("hello from cli"), 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-kem-768", "--id", "service-a")
	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-dsa-65", "--id", "signer-a")

	var encrypted bytes.Buffer
	runOKWithOutput(t, nil, &encrypted, "encrypt", "--store", storeDir, "--key", "service-a", messageFile)
	if !strings.Contains(encrypted.String(), `"schema": "pqc.envelope.v1"`) {
		t.Fatalf("encrypted output missing envelope schema: %s", encrypted.String())
	}

	var decrypted bytes.Buffer
	runOKWithOutput(t, bytes.NewReader(encrypted.Bytes()), &decrypted, "decrypt", "--store", storeDir)
	if decrypted.String() != "hello from cli" {
		t.Fatalf("decrypted = %q", decrypted.String())
	}

	signatureFile := filepath.Join(t.TempDir(), "message.sig")
	var signature bytes.Buffer
	runOKWithOutput(t, nil, &signature, "sign", "--store", storeDir, "--key", "signer-a", "--context", "test", messageFile)
	if err := os.WriteFile(signatureFile, signature.Bytes(), 0o600); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, "verify", "--store", storeDir, "--key", "signer-a", messageFile, signatureFile)
	if strings.TrimSpace(verified.String()) != "OK" {
		t.Fatalf("verify output = %q", verified.String())
	}
}

func TestCLIAgeStoreSmoke(t *testing.T) {
	storeDir := t.TempDir()
	messageFile := filepath.Join(t.TempDir(), "message.txt")
	if err := os.WriteFile(messageFile, []byte("hello encrypted store"), 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	common := []string{"--store", storeDir, "--store-type", "age", "--age-passphrase", "test passphrase"}
	runOK(t, nil, append([]string{"keys", "create"}, append(common, "--type", "ml-kem-768", "--id", "service-a")...)...)

	var encrypted bytes.Buffer
	runOKWithOutput(t, nil, &encrypted, append([]string{"encrypt"}, append(common, "--key", "service-a", messageFile)...)...)

	var decrypted bytes.Buffer
	runOKWithOutput(t, bytes.NewReader(encrypted.Bytes()), &decrypted, append([]string{"decrypt"}, common...)...)
	if decrypted.String() != "hello encrypted store" {
		t.Fatalf("decrypted = %q", decrypted.String())
	}
}

func TestCLIRemoteSmoke(t *testing.T) {
	manager := newRemoteTestManager(t)
	server := newRemoteTestServer(t, manager, "remote-token")
	defer server.Close()

	messageFile := filepath.Join(t.TempDir(), "message.txt")
	if err := os.WriteFile(messageFile, []byte("hello remote cli"), 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	common := []string{"--remote", server.URL, "--token", "remote-token"}
	runOK(t, nil, append([]string{"keys", "create"}, append(common, "--type", "ml-kem-768", "--id", "service-a")...)...)
	runOK(t, nil, append([]string{"keys", "create"}, append(common, "--type", "ml-dsa-65", "--id", "signer-a")...)...)

	var listed bytes.Buffer
	runOKWithOutput(t, nil, &listed, append([]string{"keys", "list"}, common...)...)
	if !strings.Contains(listed.String(), `"id": "service-a"`) {
		t.Fatalf("remote list missing key: %s", listed.String())
	}

	var encrypted bytes.Buffer
	runOKWithOutput(t, nil, &encrypted, append([]string{"encrypt"}, append(common, "--key", "service-a", messageFile)...)...)

	var decrypted bytes.Buffer
	runOKWithOutput(t, bytes.NewReader(encrypted.Bytes()), &decrypted, append([]string{"decrypt"}, common...)...)
	if decrypted.String() != "hello remote cli" {
		t.Fatalf("decrypted = %q", decrypted.String())
	}

	signatureFile := filepath.Join(t.TempDir(), "message.sig")
	var signature bytes.Buffer
	runOKWithOutput(t, nil, &signature, append([]string{"sign"}, append(common, "--key", "signer-a", messageFile)...)...)
	if err := os.WriteFile(signatureFile, signature.Bytes(), 0o600); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, append([]string{"verify"}, append(common, "--key", "signer-a", messageFile, signatureFile)...)...)
	if strings.TrimSpace(verified.String()) != "OK" {
		t.Fatalf("verify output = %q", verified.String())
	}
}

func TestCLIRemoteRejectsLocalStoreFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"keys", "list", "--remote", "http://127.0.0.1:1", "--store", t.TempDir()}, bytes.NewReader(nil), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "--store cannot be used with --remote") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCLIRemoteHTTPSWithCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer remote-token" {
			writeRemoteTestError(w, http.StatusUnauthorized, http.ErrNoCookie)
			return
		}
		if r.URL.Path != "/v1/keys" {
			writeRemoteTestError(w, http.StatusNotFound, http.ErrMissingFile)
			return
		}
		writeRemoteTestResult(w, []pqc.KeyMetadata{}, nil)
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	var stdout bytes.Buffer
	runOKWithOutput(t, nil, &stdout, "keys", "list", "--remote", server.URL, "--token", "remote-token", "--tls-ca", caFile)
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCLIRemoteHTTPSWithClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPEM := newTestCA(t)
	serverCertPEM, serverKeyPEM := newTestCert(t, caCert, caKey, testCertRequest{
		CommonName: "localhost",
		DNSNames:   []string{"localhost"},
		ServerAuth: true,
	})
	clientCertPEM, clientKeyPEM := newTestCert(t, caCert, caKey, testCertRequest{
		CommonName: "pqc-cli",
		ClientAuth: true,
	})

	caFile := writeTestPEM(t, dir, "ca.pem", caPEM)
	clientCertFile := writeTestPEM(t, dir, "client.crt", clientCertPEM)
	clientKeyFile := writeTestPEM(t, dir, "client.key", clientKeyPEM)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server key pair: %v", err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append client ca")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "pqc-cli" {
			writeRemoteTestError(w, http.StatusForbidden, http.ErrNoCookie)
			return
		}
		writeRemoteTestResult(w, []pqc.KeyMetadata{}, nil)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	var stdout bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&stdout,
		"keys", "list",
		"--remote", server.URL,
		"--tls-ca", caFile,
		"--tls-server-name", "localhost",
		"--tls-client-cert", clientCertFile,
		"--tls-client-key", clientKeyFile,
	)
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCLIAuditCheckpointAndVerify(t *testing.T) {
	storeDir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	checkpointPath := filepath.Join(t.TempDir(), "audit-checkpoint.json")

	runOK(t, nil, "keys", "create", "--store", storeDir, "--audit-log", auditPath, "--type", "ml-dsa-65", "--id", "audit-signer")
	runOK(t, nil, "keys", "create", "--store", storeDir, "--audit-log", auditPath, "--type", "ml-kem-768", "--id", "service-a")

	var checkpoint bytes.Buffer
	runOKWithOutput(t, nil, &checkpoint, "audit", "checkpoint", "--store", storeDir, "--audit", auditPath, "--sign-key", "audit-signer")
	if err := os.WriteFile(checkpointPath, checkpoint.Bytes(), 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	if !strings.Contains(checkpoint.String(), `"schema": "pqc.audit-checkpoint.v1"`) {
		t.Fatalf("checkpoint missing schema: %s", checkpoint.String())
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, "audit", "verify", "--store", storeDir, "--audit", auditPath, "--checkpoint", checkpointPath)
	if strings.TrimSpace(verified.String()) != "OK" {
		t.Fatalf("verify output = %q", verified.String())
	}
}

func TestCLITransparencyCheckpointAndInventory(t *testing.T) {
	storeDir := t.TempDir()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "transparency.json")
	revocationPath := filepath.Join(dir, "revocations.json")

	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-dsa-65", "--id", "org-root")
	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-kem-768", "--id", "service-a")

	var inventory bytes.Buffer
	runOKWithOutput(t, nil, &inventory, "inventory", "scan", "--store", storeDir)
	if !strings.Contains(inventory.String(), `"public_key_fingerprint": "sha256:`) {
		t.Fatalf("inventory missing fingerprint: %s", inventory.String())
	}

	var revoked bytes.Buffer
	runOKWithOutput(t, nil, &revoked, "transparency", "revoke", "--revocations", revocationPath, "--key", "service-a", "--reason", "key-compromise")
	if !strings.Contains(revoked.String(), `"type": "key"`) || !strings.Contains(revoked.String(), `"subject": "service-a"`) {
		t.Fatalf("revocation output missing event data: %s", revoked.String())
	}
	if !strings.Contains(revoked.String(), `"reason": "key-compromise"`) {
		t.Fatalf("revocation output missing canonical reason: %s", revoked.String())
	}
	var duplicateStdout, duplicateStderr bytes.Buffer
	if code := run([]string{"transparency", "revoke", "--revocations", revocationPath, "--key", "service-a", "--reason", "cessation-of-operation"}, bytes.NewReader(nil), &duplicateStdout, &duplicateStderr); code == 0 {
		t.Fatalf("expected duplicate revocation to fail, stdout: %s", duplicateStdout.String())
	}

	var bundle bytes.Buffer
	runOKWithOutput(t, nil, &bundle, "transparency", "checkpoint", "--store", storeDir, "--sign-key", "org-root", "--include-revocations", "--revocations", revocationPath)
	if err := os.WriteFile(bundlePath, bundle.Bytes(), 0o600); err != nil {
		t.Fatalf("write transparency bundle: %v", err)
	}
	if !strings.Contains(bundle.String(), `"schema": "pqc.transparency-bundle.v1"`) {
		t.Fatalf("bundle missing schema: %s", bundle.String())
	}
	if !strings.Contains(bundle.String(), `"revocation_count": 1`) || !strings.Contains(bundle.String(), `"revocations":`) {
		t.Fatalf("bundle missing revocation state: %s", bundle.String())
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, "transparency", "verify", "--store", storeDir, bundlePath)
	if strings.TrimSpace(verified.String()) != "OK" {
		t.Fatalf("verify output = %q", verified.String())
	}
}

func TestCLIProfilesIssueAndVerifyArtifact(t *testing.T) {
	storeDir := t.TempDir()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "mtc-input.json")
	x509InputPath := filepath.Join(dir, "x509-ml-dsa-input.json")
	compositeInputPath := filepath.Join(dir, "composite-x509-input.json")
	fndsaInputPath := filepath.Join(dir, "fndsa-input.json")
	artifactPath := filepath.Join(dir, "artifact.json")
	x509ArtifactPath := filepath.Join(dir, "x509-ml-dsa-artifact.json")
	compositeArtifactPath := filepath.Join(dir, "composite-x509-artifact.json")
	fndsaArtifactPath := filepath.Join(dir, "fndsa-artifact.json")
	publicKeyPath := filepath.Join(dir, "org-root.public.json")
	if err := os.WriteFile(inputPath, []byte(`{"certificate_type":"landmark","tree_size":4400000,"hash_algorithm":"sha256","checkpoint":"dev"}`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(x509InputPath, []byte(`{"signature_algorithm":"ml-dsa-44","subject_public_key_algorithm":"ml-dsa-44","certificate_role":"leaf","chain_signature_count":5,"chain_public_key_count":2,"subject":"example.com","dns_names":["example.com"]}`), 0o600); err != nil {
		t.Fatalf("write x509 input: %v", err)
	}
	if err := os.WriteFile(compositeInputPath, []byte(`{"composite_algorithm":"id-MLDSA44-RSA2048-PSS-SHA256","certificate_role":"leaf","chain_signature_count":5,"chain_public_key_count":2,"subject":"example.com","dns_names":["example.com"]}`), 0o600); err != nil {
		t.Fatalf("write composite input: %v", err)
	}
	if err := os.WriteFile(fndsaInputPath, []byte(`{"parameter_set":"fn-dsa-512","certificate_role":"intermediate","chain_signature_count":5,"chain_public_key_count":2,"subject":"Example Intermediate CA","key_usage":["keyCertSign","cRLSign"]}`), 0o600); err != nil {
		t.Fatalf("write fndsa input: %v", err)
	}

	var profiles bytes.Buffer
	runOKWithOutput(t, nil, &profiles, "profiles", "list")
	for _, want := range []string{`"id": "mtc"`, `"id": "composite-x509"`, `"id": "fndsa"`} {
		if !strings.Contains(profiles.String(), want) {
			t.Fatalf("profiles list missing %s: %s", want, profiles.String())
		}
	}
	for _, removed := range []string{`"id": "kemtls"`, `"id": "ica-suppression"`, `"id": "nist-onramp"`} {
		if strings.Contains(profiles.String(), removed) {
			t.Fatalf("profiles list still contains removed profile %s: %s", removed, profiles.String())
		}
	}

	var estimate bytes.Buffer
	runOKWithOutput(t, nil, &estimate, "profiles", "estimate", "mtc")
	if !strings.Contains(estimate.String(), `"landmark_inclusion_proof"`) {
		t.Fatalf("estimate missing metric: %s", estimate.String())
	}
	if !strings.Contains(estimate.String(), `"value": 736`) {
		t.Fatalf("estimate missing default MTC overhead: %s", estimate.String())
	}

	var treeEstimate bytes.Buffer
	runOKWithOutput(t, nil, &treeEstimate, "profiles", "estimate", "mtc", "--input", inputPath)
	if !strings.Contains(treeEstimate.String(), `"proof_hashes": 23`) {
		t.Fatalf("tree estimate missing proof hash evidence: %s", treeEstimate.String())
	}

	var help bytes.Buffer
	runOKWithOutput(t, nil, &help, "profiles", "help", "mtc")
	if !strings.Contains(help.String(), "supported version: draft-ietf-plants-merkle-tree-certs-04") {
		t.Fatalf("profile help missing supported draft: %s", help.String())
	}

	var x509Help bytes.Buffer
	runOKWithOutput(t, nil, &x509Help, "profiles", "help", "x509-ml-dsa")
	for _, want := range []string{"supported version: fips-204+rfc-9881", "NIST FIPS 204", "IETF RFC 9881"} {
		if !strings.Contains(x509Help.String(), want) {
			t.Fatalf("x509 profile help missing %q: %s", want, x509Help.String())
		}
	}

	var x509Estimate bytes.Buffer
	runOKWithOutput(t, nil, &x509Estimate, "profiles", "estimate", "x509-ml-dsa")
	for _, want := range []string{`"value": 14724`, `"drop_in_compatible": true`, `"web_tls_viable": false`} {
		if !strings.Contains(x509Estimate.String(), want) {
			t.Fatalf("x509 estimate missing %s: %s", want, x509Estimate.String())
		}
	}

	var compositeHelp bytes.Buffer
	runOKWithOutput(t, nil, &compositeHelp, "profiles", "help", "composite-x509")
	for _, want := range []string{"supported version: draft-ietf-lamps-pq-composite-sigs-latest@2026-06-15", "published 2026-06-15", "https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html"} {
		if !strings.Contains(compositeHelp.String(), want) {
			t.Fatalf("composite profile help missing %q: %s", want, compositeHelp.String())
		}
	}

	var compositeEstimate bytes.Buffer
	runOKWithOutput(t, nil, &compositeEstimate, "profiles", "estimate", "composite-x509", "--input", compositeInputPath)
	for _, want := range []string{`"value": 16544`, `"protocol_compatible": true`, `"web_tls_viable": false`, `"composite_algorithm": "id-MLDSA44-RSA2048-PSS-SHA256"`} {
		if !strings.Contains(compositeEstimate.String(), want) {
			t.Fatalf("composite estimate missing %s: %s", want, compositeEstimate.String())
		}
	}

	var fndsaHelp bytes.Buffer
	runOKWithOutput(t, nil, &fndsaHelp, "profiles", "help", "fndsa")
	for _, want := range []string{"supported version: draft-ietf-lamps-fn-dsa-certificates-00@2026-05-20", "forthcoming NIST FIPS 206", "HashFN-DSA is intentionally rejected"} {
		if !strings.Contains(fndsaHelp.String(), want) {
			t.Fatalf("fndsa profile help missing %q: %s", want, fndsaHelp.String())
		}
	}

	var fndsaEstimate bytes.Buffer
	runOKWithOutput(t, nil, &fndsaEstimate, "profiles", "estimate", "fndsa", "--input", fndsaInputPath)
	for _, want := range []string{`"value": 5124`, `"drop_in_compatible": true`, `"parameter_set": "fn-dsa-512"`, `"web_tls_viable": false`, `"x509_oid_status": "tbd"`} {
		if !strings.Contains(fndsaEstimate.String(), want) {
			t.Fatalf("fndsa estimate missing %s: %s", want, fndsaEstimate.String())
		}
	}

	var shown bytes.Buffer
	runOKWithOutput(t, nil, &shown, "profiles", "show", "mtc")
	if !strings.Contains(shown.String(), `"supported_draft": "draft-ietf-plants-merkle-tree-certs-04"`) {
		t.Fatalf("profile show missing supported draft: %s", shown.String())
	}

	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-dsa-65", "--id", "org-root")

	var x509Artifact bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&x509Artifact,
		"issue",
		"--store", storeDir,
		"--profile", "x509-ml-dsa",
		"--sign-key", "org-root",
		"--subject", "example.com",
		"--dns", "example.com",
		"--input", x509InputPath,
	)
	for _, want := range []string{`"profile": "x509-ml-dsa"`, `"profile_version": "fips-204+rfc-9881"`, `"type": "x509-ml-dsa-certificate"`, `"signature_algorithm": "ml-dsa-44"`} {
		if !strings.Contains(x509Artifact.String(), want) {
			t.Fatalf("x509 artifact missing %s: %s", want, x509Artifact.String())
		}
	}
	if err := os.WriteFile(x509ArtifactPath, x509Artifact.Bytes(), 0o600); err != nil {
		t.Fatalf("write x509 artifact: %v", err)
	}

	var compositeArtifact bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&compositeArtifact,
		"issue",
		"--store", storeDir,
		"--profile", "composite-x509",
		"--sign-key", "org-root",
		"--subject", "example.com",
		"--dns", "example.com",
		"--input", compositeInputPath,
	)
	for _, want := range []string{`"profile": "composite-x509"`, `"profile_version": "draft-ietf-lamps-pq-composite-sigs-latest@2026-06-15"`, `"type": "composite-x509-certificate"`, `"composite_algorithm": "id-MLDSA44-RSA2048-PSS-SHA256"`} {
		if !strings.Contains(compositeArtifact.String(), want) {
			t.Fatalf("composite artifact missing %s: %s", want, compositeArtifact.String())
		}
	}
	if err := os.WriteFile(compositeArtifactPath, compositeArtifact.Bytes(), 0o600); err != nil {
		t.Fatalf("write composite artifact: %v", err)
	}

	var fndsaArtifact bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&fndsaArtifact,
		"issue",
		"--store", storeDir,
		"--profile", "fndsa",
		"--sign-key", "org-root",
		"--subject", "Example Intermediate CA",
		"--input", fndsaInputPath,
	)
	for _, want := range []string{`"profile": "fndsa"`, `"profile_version": "draft-ietf-lamps-fn-dsa-certificates-00@2026-05-20"`, `"type": "fndsa-certificate"`, `"parameter_set": "fn-dsa-512"`} {
		if !strings.Contains(fndsaArtifact.String(), want) {
			t.Fatalf("fndsa artifact missing %s: %s", want, fndsaArtifact.String())
		}
	}
	if err := os.WriteFile(fndsaArtifactPath, fndsaArtifact.Bytes(), 0o600); err != nil {
		t.Fatalf("write fndsa artifact: %v", err)
	}

	var artifact bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&artifact,
		"issue",
		"--store", storeDir,
		"--profile", "mtc",
		"--sign-key", "org-root",
		"--subject", "example.com",
		"--dns", "example.com",
		"--input", inputPath,
	)
	for _, want := range []string{`"schema": "pqc.profile-artifact.v1"`, `"profile": "mtc"`, `"profile_version": "draft-ietf-plants-merkle-tree-certs-04"`, `"type": "merkle-tree-certificate"`, `"signature":`} {
		if !strings.Contains(artifact.String(), want) {
			t.Fatalf("artifact missing %s: %s", want, artifact.String())
		}
	}
	if err := os.WriteFile(artifactPath, artifact.Bytes(), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	var publicKey bytes.Buffer
	runOKWithOutput(t, nil, &publicKey, "keys", "public", "--store", storeDir, "--id", "org-root")
	if err := os.WriteFile(publicKeyPath, publicKey.Bytes(), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, "verify-artifact", "--public-key", publicKeyPath, artifactPath)
	if !strings.Contains(verified.String(), `"ok": true`) {
		t.Fatalf("verify-artifact output = %s", verified.String())
	}

	var x509Verified bytes.Buffer
	runOKWithOutput(t, nil, &x509Verified, "verify-artifact", "--public-key", publicKeyPath, x509ArtifactPath)
	if !strings.Contains(x509Verified.String(), `"ok": true`) {
		t.Fatalf("verify x509 artifact output = %s", x509Verified.String())
	}

	var compositeVerified bytes.Buffer
	runOKWithOutput(t, nil, &compositeVerified, "verify-artifact", "--public-key", publicKeyPath, compositeArtifactPath)
	if !strings.Contains(compositeVerified.String(), `"ok": true`) {
		t.Fatalf("verify composite artifact output = %s", compositeVerified.String())
	}

	var fndsaVerified bytes.Buffer
	runOKWithOutput(t, nil, &fndsaVerified, "verify-artifact", "--public-key", publicKeyPath, fndsaArtifactPath)
	if !strings.Contains(fndsaVerified.String(), `"ok": true`) {
		t.Fatalf("verify fndsa artifact output = %s", fndsaVerified.String())
	}
}

func TestCLITLSInspectJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	var report bytes.Buffer
	runOKWithOutput(t, nil, &report, "tls", "inspect", "--json", "--ca", caFile, parsed.Host)
	if !strings.Contains(report.String(), `"target": "`+parsed.Host+`"`) {
		t.Fatalf("report missing target: %s", report.String())
	}
	if !strings.Contains(report.String(), `"verified": true`) {
		t.Fatalf("report not verified: %s", report.String())
	}
	if !strings.Contains(report.String(), `"verification_mode": "custom"`) {
		t.Fatalf("report missing custom verification mode: %s", report.String())
	}
}

func TestCLITLSReadinessAndInventoryPolicy(t *testing.T) {
	t.Setenv("PQC_REMOTE", "")
	t.Setenv("PQC_API_TOKEN", "")
	t.Setenv("PQC_STORE_TYPE", "file")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	caFile := filepath.Join(dir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	var tlsOut bytes.Buffer
	runOKWithOutput(t, nil, &tlsOut, "tls", "readiness", "--json", "--ca", caFile, parsed.Host)
	var tlsReport pqc.TLSReport
	if err := json.Unmarshal(tlsOut.Bytes(), &tlsReport); err != nil {
		t.Fatalf("decode tls readiness report: %v\n%s", err, tlsOut.String())
	}
	if tlsReport.Readiness == nil {
		t.Fatalf("missing readiness: %s", tlsOut.String())
	}
	if tlsReport.Readiness.Policy.ID != pqc.TLSReadinessPolicyPublicWeb2029 {
		t.Fatalf("policy = %q", tlsReport.Readiness.Policy.ID)
	}
	if tlsReport.Readiness.CertificateValidityDays == 0 {
		t.Fatalf("missing validity days: %+v", tlsReport.Readiness)
	}
	if tlsReport.Readiness.RecommendedRenewalCadenceDays != 30 {
		t.Fatalf("cadence = %d, want 30", tlsReport.Readiness.RecommendedRenewalCadenceDays)
	}
	if !tlsReport.Readiness.Verified {
		t.Fatalf("expected verified readiness report: %+v", tlsReport.Readiness)
	}
	if tlsReport.VerificationMode != pqc.TLSVerificationCustom {
		t.Fatalf("verification mode = %q", tlsReport.VerificationMode)
	}

	var inventoryOut bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&inventoryOut,
		"inventory", "scan",
		"--store", storeDir,
		"--target", parsed.Host,
		"--target-ca", caFile,
		"--policy", "public-web-2029",
	)
	var inventory pqc.InventoryReport
	if err := json.Unmarshal(inventoryOut.Bytes(), &inventory); err != nil {
		t.Fatalf("decode inventory report: %v\n%s", err, inventoryOut.String())
	}
	if inventory.Policy != pqc.TLSReadinessPolicyPublicWeb2029 {
		t.Fatalf("inventory policy = %q", inventory.Policy)
	}
	if len(inventory.Targets) != 1 || inventory.Targets[0].Readiness == nil {
		t.Fatalf("missing inventory readiness: %+v", inventory)
	}
	if inventory.Targets[0].Readiness.Policy.MaxValidityDays != 47 {
		t.Fatalf("max validity = %d", inventory.Targets[0].Readiness.Policy.MaxValidityDays)
	}

	var targetOnlyOut bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&targetOnlyOut,
		"inventory", "scan",
		"--target", parsed.Host,
		"--target-ca", caFile,
		"--policy", "public-web-2029",
	)
	var targetOnly pqc.InventoryReport
	if err := json.Unmarshal(targetOnlyOut.Bytes(), &targetOnly); err != nil {
		t.Fatalf("decode target-only inventory report: %v\n%s", err, targetOnlyOut.String())
	}
	if len(targetOnly.Keys) != 0 {
		t.Fatalf("target-only scan unexpectedly opened a key store: %+v", targetOnly.Keys)
	}
	if len(targetOnly.Targets) != 1 || targetOnly.Targets[0].Readiness == nil {
		t.Fatalf("missing target-only readiness: %+v", targetOnly)
	}

	var readinessOut bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&readinessOut,
		"readiness", "scan",
		"--target", parsed.Host,
		"--target-ca", caFile,
	)
	var readiness pqc.ReadinessScan
	if err := json.Unmarshal(readinessOut.Bytes(), &readiness); err != nil {
		t.Fatalf("decode readiness scan: %v\n%s", err, readinessOut.String())
	}
	if readiness.Schema != pqc.ReadinessScanSchema {
		t.Fatalf("readiness schema = %q", readiness.Schema)
	}
	if readiness.Policy != pqc.TLSReadinessPolicyPublicWeb2029 {
		t.Fatalf("readiness policy = %q", readiness.Policy)
	}
	if len(readiness.Categories) == 0 {
		t.Fatalf("readiness categories missing: %+v", readiness)
	}
	if readiness.Coverage.Confidence != "target-only" {
		t.Fatalf("readiness confidence = %q", readiness.Coverage.Confidence)
	}
	if readiness.Coverage.CustomVerifiedTargetCount != 1 {
		t.Fatalf("custom verified count = %d", readiness.Coverage.CustomVerifiedTargetCount)
	}
	if readinessCategoryByID(readiness, "webpki-mtc-candidate").Applies {
		t.Fatalf("custom CA target should not be a WebPKI MTC candidate: %+v", readiness)
	}
	if !readinessCategoryByID(readiness, "private-pki-pq-x509-candidate").Applies {
		t.Fatalf("custom CA target should be a private PKI candidate: %+v", readiness)
	}
	if len(readiness.Inventory.Targets) != 1 || readiness.Inventory.Targets[0].Readiness == nil {
		t.Fatalf("readiness scan missing target facts: %+v", readiness.Inventory)
	}

	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-dsa-65", "--id", "readiness-signer")
	var storeReadinessOut bytes.Buffer
	runOKWithOutput(
		t,
		nil,
		&storeReadinessOut,
		"readiness", "scan",
		"--store", storeDir,
		"--target", parsed.Host,
		"--target-ca", caFile,
	)
	var storeReadiness pqc.ReadinessScan
	if err := json.Unmarshal(storeReadinessOut.Bytes(), &storeReadiness); err != nil {
		t.Fatalf("decode store readiness scan: %v\n%s", err, storeReadinessOut.String())
	}
	if len(storeReadiness.Inventory.Keys) == 0 {
		t.Fatalf("readiness scan did not include store keys: %+v", storeReadiness.Inventory)
	}
	if storeReadiness.Coverage.Confidence != "private-targets" {
		t.Fatalf("store readiness confidence = %q", storeReadiness.Coverage.Confidence)
	}
}

func TestCLIMTCLogFlow(t *testing.T) {
	storeDir := t.TempDir()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mtc-log.json")
	publicKeyPath := filepath.Join(dir, "org-root.public.json")
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	proofPath := filepath.Join(dir, "proof.json")

	runOK(t, nil, "keys", "create", "--store", storeDir, "--type", "ml-dsa-65", "--id", "org-root")

	var publicKey bytes.Buffer
	runOKWithOutput(t, nil, &publicKey, "keys", "public", "--store", storeDir, "--id", "org-root")
	if err := os.WriteFile(publicKeyPath, publicKey.Bytes(), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var initialized bytes.Buffer
	runOKWithOutput(t, nil, &initialized, "mtc", "log", "init", "--log", logPath)
	if !strings.Contains(initialized.String(), `"schema": "pqc.mtc-log.v1"`) {
		t.Fatalf("init output missing schema: %s", initialized.String())
	}

	var issued bytes.Buffer
	runOKWithOutput(t, nil, &issued, "mtc", "issue", "--log", logPath, "--subject", "example.com", "--public-key", publicKeyPath)
	if !strings.Contains(issued.String(), `"subject": "example.com"`) || !strings.Contains(issued.String(), `"leaf_hash": "`) {
		t.Fatalf("issue output missing entry data: %s", issued.String())
	}

	revocationPath := filepath.Join(dir, "mtc-revocations.json")
	var revoked bytes.Buffer
	runOKWithOutput(t, nil, &revoked, "mtc", "revoke", "--log", logPath, "--revocations", revocationPath, "--index", "0", "--reason", "key-compromise")
	if !strings.Contains(revoked.String(), `"type": "mtc-leaf"`) || !strings.Contains(revoked.String(), `"subject": "0"`) {
		t.Fatalf("MTC revocation output missing event data: %s", revoked.String())
	}
	if !strings.Contains(revoked.String(), `"mtc_leaf_index": 0`) {
		t.Fatalf("MTC revocation output missing metadata: %s", revoked.String())
	}

	var checkpoint bytes.Buffer
	runOKWithOutput(t, nil, &checkpoint, "mtc", "checkpoint", "--store", storeDir, "--log", logPath, "--sign-key", "org-root")
	if !strings.Contains(checkpoint.String(), `"schema": "pqc.mtc-checkpoint.v1"`) || !strings.Contains(checkpoint.String(), `"signature":`) {
		t.Fatalf("checkpoint output missing signed checkpoint: %s", checkpoint.String())
	}
	if err := os.WriteFile(checkpointPath, checkpoint.Bytes(), 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	var proof bytes.Buffer
	runOKWithOutput(t, nil, &proof, "mtc", "prove", "--log", logPath, "--leaf", "0")
	if !strings.Contains(proof.String(), `"schema": "pqc.mtc-proof.v1"`) || !strings.Contains(proof.String(), `"leaf_index": 0`) {
		t.Fatalf("proof output missing proof: %s", proof.String())
	}
	if err := os.WriteFile(proofPath, proof.Bytes(), 0o600); err != nil {
		t.Fatalf("write proof: %v", err)
	}

	var verified bytes.Buffer
	runOKWithOutput(t, nil, &verified, "mtc", "verify", "--store", storeDir, "--proof", proofPath, "--checkpoint", checkpointPath)
	if strings.TrimSpace(verified.String()) != "OK" {
		t.Fatalf("verify output = %q", verified.String())
	}

	var parsedCheckpoint pqc.MTCCheckpoint
	if err := json.Unmarshal(checkpoint.Bytes(), &parsedCheckpoint); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	var parsedPublicKey pqc.PublicKey
	if err := json.Unmarshal(publicKey.Bytes(), &parsedPublicKey); err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	treeheadEntry, err := pqc.NewMTCTreeheadEntry("https://mtc.example.test/treeheads", "test-log", parsedCheckpoint, parsedPublicKey, time.Now().UTC())
	if err != nil {
		t.Fatalf("treehead entry: %v", err)
	}
	treeheadCache := pqc.NewMTCTreeheadCache("https://mtc.example.test/treeheads", []pqc.MTCTreeheadEntry{treeheadEntry}, time.Now().UTC())
	treeheadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/checkpoint" {
			_, _ = w.Write(checkpoint.Bytes())
			return
		}
		_ = json.NewEncoder(w).Encode(treeheadCache)
	}))
	defer treeheadServer.Close()

	treeheadDir := filepath.Join(dir, "treeheads")
	var fetched bytes.Buffer
	runOKWithOutput(t, nil, &fetched, "mtc", "treeheads", "fetch", "--source", treeheadServer.URL, "--out", treeheadDir)
	if !strings.Contains(fetched.String(), "fetched_treeheads: 1") {
		t.Fatalf("fetch output = %q", fetched.String())
	}

	var treeheadsVerified bytes.Buffer
	runOKWithOutput(t, nil, &treeheadsVerified, "mtc", "treeheads", "verify", treeheadDir)
	if strings.TrimSpace(treeheadsVerified.String()) != "OK verified_treeheads=1" {
		t.Fatalf("treeheads verify output = %q", treeheadsVerified.String())
	}

	exportDir := filepath.Join(dir, "openssl-treeheads")
	var exported bytes.Buffer
	runOKWithOutput(t, nil, &exported, "mtc", "treeheads", "export", "--cache", treeheadDir, "--format", "openssl-dir", "--out", exportDir)
	if !strings.Contains(exported.String(), "exported_treeheads: 1") {
		t.Fatalf("export output = %q", exported.String())
	}
	if _, err := os.Stat(filepath.Join(exportDir, "index.json")); err != nil {
		t.Fatalf("missing exported index: %v", err)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "README.pqc-treeheads")); err != nil {
		t.Fatalf("missing exported readme: %v", err)
	}

	if err := os.WriteFile(filepath.Join(treeheadDir, "treeheads", "stale.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write stale treehead: %v", err)
	}
	var staleStdout, staleStderr bytes.Buffer
	code := run([]string{"mtc", "treeheads", "verify", "--json", treeheadDir}, bytes.NewReader(nil), &staleStdout, &staleStderr)
	if code == 0 {
		t.Fatalf("expected stale treehead cache verification to fail")
	}
	if !strings.Contains(staleStdout.String(), `"ok": false`) {
		t.Fatalf("stale verify json = %s, stderr = %s", staleStdout.String(), staleStderr.String())
	}

	singleCheckpointDir := filepath.Join(dir, "single-checkpoint-treeheads")
	runOK(t, nil, "mtc", "treeheads", "fetch", "--source", treeheadServer.URL+"/checkpoint", "--public-key", publicKeyPath, "--log-id", "test-log", "--out", singleCheckpointDir)
	runOK(t, nil, "mtc", "treeheads", "verify", singleCheckpointDir)
}

func runOK(t *testing.T, stdin *bytes.Reader, args ...string) {
	t.Helper()
	runOKWithOutput(t, stdin, &bytes.Buffer{}, args...)
}

func runOKWithOutput(t *testing.T, stdin *bytes.Reader, stdout *bytes.Buffer, args ...string) {
	t.Helper()
	var input anyReader
	if stdin != nil {
		input = stdin
	} else {
		input = bytes.NewReader(nil)
	}
	var stderr bytes.Buffer
	if code := run(args, input, stdout, &stderr); code != 0 {
		t.Fatalf("run(%v) exit %d, stderr: %s", args, code, stderr.String())
	}
}

func readinessCategoryByID(scan pqc.ReadinessScan, id string) *pqc.ReadinessCategory {
	for i := range scan.Categories {
		if scan.Categories[i].ID == id {
			return &scan.Categories[i]
		}
	}
	return nil
}

type anyReader interface {
	Read([]byte) (int, error)
}

func newRemoteTestManager(t *testing.T) *pqc.Manager {
	t.Helper()
	store, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return pqc.NewManager(store)
}

func newRemoteTestServer(t *testing.T, manager *pqc.Manager, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		switch r.Method {
		case http.MethodGet:
			keys, err := manager.List(r.Context())
			writeRemoteTestResult(w, keys, err)
		case http.MethodPost:
			var req struct {
				ID        string `json:"id"`
				Algorithm string `json:"algorithm"`
			}
			if !decodeRemoteTestRequest(w, r, &req) {
				return
			}
			algorithm, err := pqc.ParseAlgorithm(req.Algorithm)
			if err != nil {
				writeRemoteTestError(w, http.StatusBadRequest, err)
				return
			}
			meta, err := manager.Generate(r.Context(), pqc.GenerateRequest{ID: req.ID, Algorithm: algorithm})
			writeRemoteTestResult(w, meta, err)
		default:
			writeRemoteTestError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		}
	})
	mux.HandleFunc("/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/keys/")
		if strings.HasSuffix(rest, "/rotate") {
			id := strings.TrimSuffix(rest, "/rotate")
			meta, err := manager.Rotate(r.Context(), id)
			writeRemoteTestResult(w, meta, err)
			return
		}
		meta, err := manager.Get(r.Context(), rest)
		writeRemoteTestResult(w, meta, err)
	})
	mux.HandleFunc("/v1/encrypt", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		var req struct {
			KeyID     string `json:"key_id"`
			Plaintext []byte `json:"plaintext"`
			AAD       []byte `json:"aad,omitempty"`
		}
		if !decodeRemoteTestRequest(w, r, &req) {
			return
		}
		env, err := manager.Encrypt(r.Context(), req.KeyID, req.Plaintext, pqc.EncryptOptions{AAD: req.AAD})
		writeRemoteTestResult(w, env, err)
	})
	mux.HandleFunc("/v1/decrypt", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		var req struct {
			Envelope pqc.Envelope `json:"envelope"`
			AAD      []byte       `json:"aad,omitempty"`
		}
		if !decodeRemoteTestRequest(w, r, &req) {
			return
		}
		plaintext, err := manager.Decrypt(r.Context(), &req.Envelope, pqc.EncryptOptions{AAD: req.AAD})
		writeRemoteTestResult(w, struct {
			Plaintext []byte `json:"plaintext"`
		}{Plaintext: plaintext}, err)
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		var req struct {
			KeyID      string `json:"key_id"`
			Message    []byte `json:"message"`
			Context    []byte `json:"context,omitempty"`
			Randomized bool   `json:"randomized,omitempty"`
		}
		if !decodeRemoteTestRequest(w, r, &req) {
			return
		}
		sig, err := manager.Sign(r.Context(), req.KeyID, req.Message, pqc.SignOptions{
			Context:    req.Context,
			Randomized: req.Randomized,
		})
		writeRemoteTestResult(w, sig, err)
	})
	mux.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, w, r, token)
		if w.Header().Get("X-Test-Auth-Failed") != "" {
			return
		}
		var req struct {
			Message   []byte                `json:"message"`
			Signature pqc.SignatureEnvelope `json:"signature"`
		}
		if !decodeRemoteTestRequest(w, r, &req) {
			return
		}
		err := manager.Verify(r.Context(), req.Message, &req.Signature)
		writeRemoteTestResult(w, struct {
			OK bool `json:"ok"`
		}{OK: err == nil}, err)
	})
	return httptest.NewServer(mux)
}

func requireBearer(t *testing.T, w http.ResponseWriter, r *http.Request, token string) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.Header().Set("X-Test-Auth-Failed", "true")
		writeRemoteTestError(w, http.StatusUnauthorized, http.ErrNoCookie)
	}
}

func decodeRemoteTestRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		writeRemoteTestError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeRemoteTestResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		writeRemoteTestError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeRemoteTestError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

type testCertRequest struct {
	CommonName string
	DNSNames   []string
	ServerAuth bool
	ClientAuth bool
}

func newTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pqc test ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}

func newTestCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, req testCertRequest) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		DNSNames:     req.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	if req.ServerAuth {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if req.ClientAuth {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func writeTestPEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
