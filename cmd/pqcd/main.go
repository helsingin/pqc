package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	pqc "github.com/helsingin/pqc"
	agefilestore "github.com/helsingin/pqc/store/agefile"
	filestore "github.com/helsingin/pqc/store/file"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	storeDir := flag.String("store", "", "key store directory (default: $PQC_STORE_DIR or ~/.pqc/keys)")
	storeType := flag.String("store-type", getenvDefault("PQC_STORE_TYPE", "file"), "store type: file or age")
	agePassphrase := flag.String("age-passphrase", os.Getenv("PQC_AGE_PASSPHRASE"), "age store passphrase (prefer $PQC_AGE_PASSPHRASE or --age-passphrase-file)")
	agePassphraseFile := flag.String("age-passphrase-file", os.Getenv("PQC_AGE_PASSPHRASE_FILE"), "file containing age store passphrase")
	auditPath := flag.String("audit", os.Getenv("PQC_AUDIT_LOG"), "JSONL audit log path (default: $PQC_AUDIT_LOG)")
	token := flag.String("token", os.Getenv("PQC_API_TOKEN"), "bearer token for HTTP API (default: $PQC_API_TOKEN)")
	tlsCert := flag.String("tls-cert", os.Getenv("PQC_TLS_CERT"), "TLS server certificate PEM file")
	tlsKey := flag.String("tls-key", os.Getenv("PQC_TLS_KEY"), "TLS server private key PEM file")
	tlsClientCA := flag.String("tls-client-ca", os.Getenv("PQC_TLS_CLIENT_CA"), "CA PEM file for verifying optional/required client certificates")
	tlsRequireClientCert := flag.Bool("tls-require-client-cert", getenvBool("PQC_TLS_REQUIRE_CLIENT_CERT", false), "require and verify client TLS certificates")
	tlsPQC := flag.Bool("tls-pqc", getenvBool("PQC_TLS_PQC", true), "prefer TLS 1.3 hybrid post-quantum key exchange groups")
	authPolicyPath := flag.String("auth-policy", os.Getenv("PQC_AUTH_POLICY"), "JSON authorization policy mapping identities to operations")
	flag.Parse()

	manager, err := openManager(*storeDir, *storeType, *agePassphrase, *agePassphraseFile, *auditPath)
	if err != nil {
		log.Fatal(err)
	}

	authPolicy, err := loadAuthPolicy(*authPolicyPath)
	if err != nil {
		log.Fatal(err)
	}

	api := &server{
		manager:     manager,
		bearerToken: *token,
		authPolicy:  authPolicy,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys", api.keys)
	mux.HandleFunc("/v1/keys/", api.key)
	mux.HandleFunc("/v1/encrypt", api.encrypt)
	mux.HandleFunc("/v1/decrypt", api.decrypt)
	mux.HandleFunc("/v1/sign", api.sign)
	mux.HandleFunc("/v1/verify", api.verify)

	tlsConfig, useTLS, err := buildServerTLSConfig(serverTLSOptions{
		CertFile:          *tlsCert,
		KeyFile:           *tlsKey,
		ClientCAFile:      *tlsClientCA,
		RequireClientCert: *tlsRequireClientCert,
		PQC:               *tlsPQC,
	})
	if err != nil {
		log.Fatal(err)
	}

	if *token == "" {
		log.Printf("pqcd bearer auth disabled; set --token or PQC_API_TOKEN to require Authorization: Bearer")
	}
	srv := &http.Server{
		Addr:      *addr,
		Handler:   api.authenticate(api.authorize(mux)),
		TLSConfig: tlsConfig,
	}
	if useTLS {
		if *tlsPQC {
			log.Printf("pqcd TLS hybrid PQC key exchange preferences enabled")
		}
		log.Printf("pqcd listening with TLS on %s", *addr)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	log.Printf("pqcd listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

type server struct {
	manager     *pqc.Manager
	bearerToken string
	authPolicy  *authPolicy
}

type createKeyRequest struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Type      string `json:"type"`
}

type encryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"`
}

type decryptRequest struct {
	Envelope pqc.Envelope `json:"envelope"`
	AAD      []byte       `json:"aad,omitempty"`
}

type decryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

type signRequest struct {
	KeyID      string `json:"key_id"`
	Message    []byte `json:"message"`
	Context    []byte `json:"context,omitempty"`
	Randomized bool   `json:"randomized,omitempty"`
}

type verifyRequest struct {
	Message   []byte                `json:"message"`
	Signature pqc.SignatureEnvelope `json:"signature"`
}

type verifyResponse struct {
	OK bool `json:"ok"`
}

func (s *server) keys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := s.manager.List(r.Context())
		writeResult(w, keys, err)
	case http.MethodPost:
		var req createKeyRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		algorithm, err := parseRequestAlgorithm(req.Algorithm, req.Type)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		meta, err := s.manager.Generate(r.Context(), pqc.GenerateRequest{
			ID:        req.ID,
			Algorithm: algorithm,
		})
		writeResult(w, meta, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *server) key(w http.ResponseWriter, r *http.Request) {
	id, action, ok := splitKeyPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		meta, err := s.manager.Get(r.Context(), id)
		writeResult(w, meta, err)
	case action == "rotate" && r.Method == http.MethodPost:
		meta, err := s.manager.Rotate(r.Context(), id)
		writeResult(w, meta, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req encryptRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	envelope, err := s.manager.Encrypt(r.Context(), req.KeyID, req.Plaintext, pqc.EncryptOptions{AAD: req.AAD})
	writeResult(w, envelope, err)
}

func (s *server) decrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req decryptRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	plaintext, err := s.manager.Decrypt(r.Context(), &req.Envelope, pqc.EncryptOptions{AAD: req.AAD})
	writeResult(w, decryptResponse{Plaintext: plaintext}, err)
}

func (s *server) sign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req signRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	signature, err := s.manager.Sign(r.Context(), req.KeyID, req.Message, pqc.SignOptions{
		Context:    req.Context,
		Randomized: req.Randomized,
	})
	writeResult(w, signature, err)
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req verifyRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if err := s.manager.Verify(r.Context(), req.Message, &req.Signature); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeResult(w, verifyResponse{OK: true}, nil)
}

func openManager(storeDir, storeType, agePassphrase, agePassphraseFile, auditPath string) (*pqc.Manager, error) {
	if storeDir == "" {
		var err error
		storeDir, err = filestore.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	store, err := openStore(storeDir, storeType, agePassphrase, agePassphraseFile)
	if err != nil {
		return nil, err
	}
	opts := []pqc.Option{}
	if auditPath != "" {
		auditor, err := pqc.NewFileAuditor(auditPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, pqc.WithAuditor(auditor))
	}
	return pqc.NewManager(store, opts...), nil
}

func openStore(storeDir, storeType, agePassphrase, agePassphraseFile string) (pqc.Store, error) {
	switch strings.ToLower(strings.TrimSpace(storeType)) {
	case "", "file":
		return filestore.New(storeDir)
	case "age", "agefile":
		passphrase, err := resolveAgePassphrase(agePassphrase, agePassphraseFile)
		if err != nil {
			return nil, err
		}
		return agefilestore.New(storeDir, passphrase)
	default:
		return nil, fmt.Errorf("unsupported store type %q", storeType)
	}
}

func resolveAgePassphrase(passphrase, passphraseFile string) (string, error) {
	if passphraseFile != "" {
		data, err := os.ReadFile(passphraseFile)
		if err != nil {
			return "", err
		}
		passphrase = strings.TrimRight(string(data), "\r\n")
	}
	if passphrase == "" {
		return "", fmt.Errorf("age store requires --age-passphrase, --age-passphrase-file, or PQC_AGE_PASSPHRASE")
	}
	return passphrase, nil
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseRequestAlgorithm(algorithm, typ string) (pqc.Algorithm, error) {
	value := strings.TrimSpace(algorithm)
	if value == "" {
		value = typ
	}
	return pqc.ParseAlgorithm(value)
}

func splitKeyPath(path string) (id string, action string, ok bool) {
	rest := strings.TrimPrefix(path, "/v1/keys/")
	if rest == path || rest == "" {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 1 && parts[0] != "" {
		id, err := url.PathUnescape(parts[0])
		return id, "", err == nil && id != ""
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "rotate" {
		id, err := url.PathUnescape(parts[0])
		return id, "rotate", err == nil && id != ""
	}
	return "", "", false
}

func decodeRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		writeError(w, http.StatusInternalServerError, err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func statusForError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, pqc.ErrKeyNotFound):
		return http.StatusNotFound
	case errors.Is(err, pqc.ErrKeyExists):
		return http.StatusConflict
	case errors.Is(err, pqc.ErrInvalidEnvelope), errors.Is(err, pqc.ErrInvalidSignature):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
}
